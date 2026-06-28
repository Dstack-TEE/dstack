// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup install` — bring up the host stack and bootstrap the KMS-in-CVM.

use crate::cid::pick_cid_start;
use crate::cli::{InstallOpts, DEFAULT_AUTH_BIN, DEFAULT_SUPERVISOR_BIN, DEFAULT_VMM_BIN};
use crate::state::{read_state, write, write_state, State};
use crate::systemd::{auth_unit_file, install_unit, tool, unit_active, unit_name, vmm_unit_file};
use anyhow::{bail, Context, Result};
use dstack_cli_core::config::{self, HostConfig, VmmRender};
use dstack_cli_core::host::Platform;
use dstack_cli_core::layout::{path_string, InstallLayout};
use dstack_cli_core::vmm::Vmm;
use dstack_cli_core::{host, ports, rpc};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as PCommand;
use std::time::Duration;

const USER_BINARIES: &[(&str, &str)] = &[("dstack", "dstack")];

const DAEMON_BINARIES: &[(&str, &str)] = &[
    ("dstack-auth", "dstack-auth"),
    ("dstack-vmm", "dstack-vmm"),
    ("supervisor", "supervisor"),
];

pub(crate) async fn cmd_install(mut o: InstallOpts) -> Result<()> {
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

    // 3. resolve paths (no side effects yet). The image dir resolves through the
    //    same helper the `image` subcommands use, so `install --prefix X` and
    //    `image pull --prefix X` always agree on where images live.
    let mut layout = InstallLayout::new(o.prefix.as_deref());
    apply_layout_overrides(&mut layout, &o);
    validate_layout(&layout)?;
    validate_install_opts(&o)?;
    let explicit_prefix = o.prefix.is_some();
    let images = crate::image::resolve_image_dir(o.image_path.as_deref(), o.prefix.as_deref());
    crate::image::validate_image_dir(&images)?;
    let mut st = read_state(&layout.state_dir).unwrap_or_default();

    let bind = o.expose.clone().unwrap_or_else(|| "127.0.0.1".to_string());
    let dashboard_addr = format!("tcp:{bind}:{}", o.dashboard_port);
    let client_url = format!("http://{bind}:{}", o.dashboard_port);
    let kms_port = resolve_kms_port(&o, &st)?;

    // 4. preflight - fail BEFORE any side effect (image download, key provider,
    //    dirs, units), so a CID/port clash can't half-install the host.
    let cid_start = pick_cid_start(o.cid_start, &host::occupied_cid_ranges())?;
    let kms_owned = kms_port_owned(&st, &client_url, kms_port, o.no_kms).await;
    let port_plan = tcp_port_plan(&o, &st, platform, &bind, &client_url, kms_port, kms_owned);
    preflight_ports(&port_plan)?;

    // 5. resolve the guest image: explicit --image, else the newest present
    //    locally. In KMS mode, bootstrap needs an image now; if the image store is
    //    empty, download the latest CPU image through the verified image path.
    //    Pinning is validated before installing managed binaries, so an
    //    incompatible image fails without leaving a half-built host install.
    let required_digest =
        (!o.no_kms && !o.allow_unpinned_image).then_some(os_image_digest_file(platform));
    o.image = crate::image::resolve_or_pull_image(
        &images,
        o.image.as_deref(),
        !o.no_kms,
        required_digest,
    )
    .await?;
    let os_image_hash = resolve_image_pin(&o, &images, platform)?;

    // 6. install the binaries managed by dstackup. The bootstrap installer only
    //    installs dstackup; this step owns the local dstack CLI and host daemons.
    prepare_managed_binaries(&mut o, &layout)?;

    // 7. lay out the installation directories.
    for dir in [
        layout.config_dir.clone(),
        layout.state_dir.clone(),
        layout.state_dir.join("certs"),
        layout.run_dir.clone(),
    ] {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    // 8. resolve the key provider - run our own unless told to use an existing
    //    one (TDX only; SNP has no SGX gramine provider).
    let (kp_addr, kp_port, kp_own_project) =
        resolve_key_provider(&o, platform, !o.no_start, &layout)?;

    // KMS host port + URL, resolved during preflight so conflicts are caught
    // before image download, builds, or systemd writes.
    let kms_urls = if o.no_kms {
        vec![]
    } else {
        vec![format!("https://10.0.2.2:{kms_port}")]
    };

    // 9. render configs.
    let vmm = config::vmm_toml(&VmmRender {
        dashboard_addr: dashboard_addr.clone(),
        image_path: images.clone(),
        qemu_path: o.qemu.clone(),
        run_dir: layout.run_dir.display().to_string(),
        vm_path: layout.state_dir.join("vm").display().to_string(),
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

    let vmm_path = layout.config_dir.join("vmm.toml");
    let kms_path = layout.config_dir.join("kms.toml");
    let allow_path = layout.config_dir.join("auth-allowlist.json");
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

    st.prefix = layout.state_dir.display().to_string();
    st.install_prefix = layout.root.as_ref().map(|p| p.display().to_string());
    st.config_dir = layout.config_dir.display().to_string();
    st.state_dir = layout.state_dir.display().to_string();
    st.cache_dir = layout.cache_dir.display().to_string();
    st.run_dir = layout.run_dir.display().to_string();
    st.allowlist_path = allow_path.display().to_string();
    st.client_url = client_url.clone();
    st.auth_port = o.auth_port;
    st.platform = platform.vmm_str().to_string();
    st.image = o.image.clone();
    let instance = effective_instance(&o, &layout, explicit_prefix);
    let auth_unit = unit_name("auth", &instance);
    let vmm_unit = unit_name("vmm", &instance);

    // 10. auth webhook systemd unit (idempotent).
    if unit_active(&auth_unit) {
        println!("  [ok] {auth_unit}.service already active");
    } else {
        install_unit(
            &auth_unit,
            &auth_unit_file(&o.auth_bin, &allow_path, o.auth_port, &layout.state_dir),
        )
        .context("installing the auth webhook unit")?;
        println!(
            "  [ok] started {auth_unit}.service on 127.0.0.1:{}",
            o.auth_port
        );
    }
    st.auth_unit = auth_unit.clone();

    // 11. VMM systemd unit (idempotent).
    if vmm_reachable(&client_url).await {
        println!("  [ok] VMM already serving at {client_url}");
    } else {
        install_unit(
            &vmm_unit,
            &vmm_unit_file(&o.vmm_bin, &vmm_path, &layout.state_dir, &auth_unit),
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
    write_state(&layout.state_dir, &st)?;

    // 12. deploy + bootstrap the KMS-in-CVM (idempotent).
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
            write_state(&layout.state_dir, &st)?;
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
    let dstack_cmd = if layout.is_default() {
        "dstack".to_string()
    } else {
        path_string(&layout.bin_dir.join("dstack"))
    };
    println!(
        "deploy an app with: sudo {dstack_cmd} deploy -c {} --port <host_port>:<vm_port>",
        layout.hello_nginx_compose().display()
    );
    Ok(())
}

fn apply_layout_overrides(layout: &mut InstallLayout, o: &InstallOpts) {
    if let Some(bin_dir) = &o.bin_dir {
        layout.bin_dir = PathBuf::from(bin_dir);
    }
    if let Some(libexec_dir) = &o.libexec_dir {
        layout.libexec_dir = PathBuf::from(libexec_dir);
    }
    if let Some(share_dir) = &o.share_dir {
        layout.share_dir = PathBuf::from(share_dir);
    }
}

fn validate_layout(layout: &InstallLayout) -> Result<()> {
    layout.validate()
}

fn effective_instance(
    o: &InstallOpts,
    layout: &InstallLayout,
    explicit_prefix: bool,
) -> Option<String> {
    o.instance.clone().or_else(|| {
        explicit_prefix
            .then(|| layout.root.as_deref().map(prefix_instance))
            .flatten()
    })
}

fn prefix_instance(prefix: &Path) -> String {
    let base = prefix
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("prefix");
    let slug = slugify_unit_part(base);
    format!(
        "{slug}-{:08x}",
        fnv1a32(prefix.to_string_lossy().as_bytes())
    )
}

fn slugify_unit_part(input: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for c in input.chars() {
        let valid = c.is_ascii_alphanumeric();
        if valid {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let slug = out.trim_matches('-');
    if slug.is_empty() {
        "prefix".to_string()
    } else {
        slug.to_string()
    }
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for b in bytes {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn prepare_managed_binaries(o: &mut InstallOpts, layout: &InstallLayout) -> Result<()> {
    if o.skip_managed_binaries {
        println!("  [ok] using configured binaries (--skip-managed-binaries)");
        return Ok(());
    }

    if o.vmm_bin == DEFAULT_VMM_BIN {
        o.vmm_bin = layout
            .libexec_dir
            .join(DEFAULT_VMM_BIN)
            .display()
            .to_string();
    }
    if o.auth_bin == DEFAULT_AUTH_BIN {
        o.auth_bin = layout
            .libexec_dir
            .join(DEFAULT_AUTH_BIN)
            .display()
            .to_string();
    }
    if o.supervisor_bin == DEFAULT_SUPERVISOR_BIN {
        o.supervisor_bin = layout
            .libexec_dir
            .join(DEFAULT_SUPERVISOR_BIN)
            .display()
            .to_string();
    }

    if o.no_start {
        println!(
            "  [ok] managed binary targets {}, {} (--no-start: not building)",
            layout.bin_dir.display(),
            layout.libexec_dir.display()
        );
        return Ok(());
    }

    let source = resolve_source_checkout(o, layout)?;
    let target_dir = layout.cargo_target_dir();
    create_build_owned_dir(&target_dir)?;
    build_managed_binaries(&source, &target_dir)?;
    install_managed_binaries(&target_dir, layout)?;
    install_share_assets(&source, layout)?;
    println!(
        "  [ok] installed dstack binaries into {}, host daemons into {}",
        layout.bin_dir.display(),
        layout.libexec_dir.display()
    );
    Ok(())
}

fn resolve_source_checkout(o: &InstallOpts, layout: &InstallLayout) -> Result<PathBuf> {
    if let Some(source) = o.source.as_deref() {
        return checked_source_checkout(PathBuf::from(source));
    }

    let cwd = env::current_dir().context("resolving current directory")?;
    if is_dstack_checkout(&cwd) {
        return checked_source_checkout(cwd);
    }

    let source = layout.source_dir();
    sync_source_cache(&source, &o.source_repo, &o.source_ref)?;
    checked_source_checkout(source)
}

fn checked_source_checkout(dir: PathBuf) -> Result<PathBuf> {
    if !is_dstack_checkout(&dir) {
        bail!("{} is not a dstack source checkout", dir.display());
    }
    dir.canonicalize()
        .with_context(|| format!("canonicalizing {}", dir.display()))
}

fn sync_source_cache(source: &Path, repo: &str, git_ref: &str) -> Result<()> {
    let parent = source
        .parent()
        .with_context(|| format!("{} has no parent directory", source.display()))?;
    create_build_owned_dir(parent)?;

    if source.exists() {
        if !is_dstack_checkout(source) || !source.join(".git").is_dir() {
            bail!(
                "{} exists but is not a dstack git checkout; pass --source DIR or remove the cache",
                source.display()
            );
        }
        println!("  [..] updating dstack source cache {}", source.display());
        run_git_at(
            source,
            ["fetch", "--tags", "origin"],
            "fetching dstack source",
        )?;
        run_git_at(
            source,
            ["checkout", git_ref],
            "checking out dstack source ref",
        )?;
        let remote_ref = format!("origin/{git_ref}");
        if git_status_at(source, ["rev-parse", "--verify", &remote_ref])? {
            run_git_at(
                source,
                ["pull", "--ff-only", "origin", git_ref],
                "fast-forwarding dstack source",
            )?;
        }
    } else {
        println!("  [..] cloning dstack source into {}", source.display());
        let mut cmd = git_command();
        let status = cmd
            .arg("clone")
            .arg(repo)
            .arg(source)
            .status()
            .context("cloning dstack source")?;
        if !status.success() {
            bail!("failed to clone dstack source from {repo}");
        }
        run_git_at(
            source,
            ["fetch", "--tags", "origin"],
            "fetching dstack tags",
        )?;
        run_git_at(
            source,
            ["checkout", git_ref],
            "checking out dstack source ref",
        )?;
    }
    Ok(())
}

fn run_git_at<const N: usize>(dir: &Path, args: [&str; N], what: &str) -> Result<()> {
    let mut cmd = git_command();
    let status = cmd
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .with_context(|| format!("{what} in {}", dir.display()))?;
    if !status.success() {
        bail!("{what} failed in {}", dir.display());
    }
    Ok(())
}

fn git_status_at<const N: usize>(dir: &Path, args: [&str; N]) -> Result<bool> {
    Ok(git_command()
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .with_context(|| format!("running git in {}", dir.display()))?
        .success())
}

fn is_dstack_checkout(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file()
        && dir.join("crates/dstack-cli").is_dir()
        && dir.join("crates/dstack-auth").is_dir()
        && dir.join("vmm").is_dir()
        && dir.join("supervisor").is_dir()
}

fn build_managed_binaries(source: &Path, target_dir: &Path) -> Result<()> {
    let mut cmd = cargo_build_command(target_dir)?;
    let target_dir_arg = path_string(target_dir);
    cmd.current_dir(source).args([
        "build",
        "--release",
        "--target-dir",
        &target_dir_arg,
        "-p",
        "dstack-cli",
        "-p",
        "dstack-auth",
        "-p",
        "dstack-vmm",
        "-p",
        "supervisor",
    ]);
    let status = cmd.status().context("building managed dstack binaries")?;
    if !status.success() {
        bail!("failed to build managed dstack binaries");
    }
    Ok(())
}

fn cargo_build_command(target_dir: &Path) -> Result<PCommand> {
    if let Some((user, home)) = sudo_build_user() {
        let cargo_home = home.join(".cargo/bin");
        let mut cmd = tool("sudo");
        cmd.args(["-H", "-u", &user, "env"]);
        cmd.arg(format!(
            "PATH={}:{}",
            cargo_home.display(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ));
        cmd.arg(format!("CARGO_TARGET_DIR={}", target_dir.display()));
        cmd.arg("cargo");
        return Ok(cmd);
    }

    let cargo =
        find_cargo().context("could not find cargo; install Rust before running install")?;
    let mut cmd = PCommand::new(cargo);
    if let Some(path) = env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("CARGO_TARGET_DIR", target_dir);
    Ok(cmd)
}

fn git_command() -> PCommand {
    if let Some((user, home)) = sudo_build_user() {
        let cargo_home = home.join(".cargo/bin");
        let mut cmd = tool("sudo");
        cmd.args(["-H", "-u", &user, "env"]);
        cmd.arg(format!(
            "PATH={}:{}",
            cargo_home.display(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ));
        cmd.arg("git");
        return cmd;
    }
    tool("git")
}

fn sudo_build_user() -> Option<(String, PathBuf)> {
    let user = env::var("SUDO_USER").ok()?;
    if user.is_empty() || user == "root" {
        return None;
    }
    let home = user_home(&user)?;
    if !home.join(".cargo/bin/cargo").is_file() {
        return None;
    }
    Some((user, home))
}

fn user_home(user: &str) -> Option<PathBuf> {
    let out = tool("getent").args(["passwd", user]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8(out.stdout).ok()?;
    let home = body.lines().next()?.split(':').nth(5)?;
    Some(PathBuf::from(home))
}

fn find_cargo() -> Option<PathBuf> {
    if let Some(cargo) = env::var_os("CARGO").map(PathBuf::from) {
        if cargo.is_file() {
            return Some(cargo);
        }
    }
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join("cargo");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    let home = env::var_os("HOME").map(PathBuf::from)?;
    let cargo = home.join(".cargo/bin/cargo");
    cargo.is_file().then_some(cargo)
}

fn create_build_owned_dir(dir: &Path) -> Result<()> {
    if let Some((user, _)) = sudo_build_user() {
        let status = tool("install")
            .args(["-d", "-m", "0755", "-o", &user])
            .arg(dir)
            .status()
            .with_context(|| format!("creating {}", dir.display()))?;
        if !status.success() {
            bail!("failed to create {}", dir.display());
        }
        return Ok(());
    }
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))
}

fn create_install_dir(dir: &Path) -> Result<()> {
    let status = tool("install")
        .args(["-d", "-m", "0755"])
        .arg(dir)
        .status()
        .with_context(|| format!("creating {}", dir.display()))?;
    if !status.success() {
        bail!("failed to create {}", dir.display());
    }
    Ok(())
}

fn install_managed_binaries(target_dir: &Path, layout: &InstallLayout) -> Result<()> {
    create_install_dir(&layout.bin_dir)?;
    create_install_dir(&layout.libexec_dir)?;

    for (built, installed, dest_dir) in USER_BINARIES
        .iter()
        .map(|(built, installed)| (*built, *installed, &layout.bin_dir))
        .chain(
            DAEMON_BINARIES
                .iter()
                .map(|(built, installed)| (*built, *installed, &layout.libexec_dir)),
        )
    {
        let src = target_dir.join("release").join(built);
        if !src.is_file() {
            bail!("expected built binary {}", src.display());
        }
        let dest = dest_dir.join(installed);
        let status = tool("install")
            .args(["-m", "0755"])
            .arg(&src)
            .arg(&dest)
            .status()
            .with_context(|| format!("installing {}", dest.display()))?;
        if !status.success() {
            bail!("failed to install {}", dest.display());
        }
    }
    Ok(())
}

fn install_share_assets(source: &Path, layout: &InstallLayout) -> Result<()> {
    fs::create_dir_all(&layout.share_dir)
        .with_context(|| format!("creating {}", layout.share_dir.display()))?;
    copy_dir_exact(
        &source.join("key-provider-build"),
        &layout.key_provider_dir(),
    )?;
    copy_dir_exact(&source.join("examples"), &layout.share_dir.join("examples"))?;
    println!(
        "  [ok] installed assets into {}",
        layout.share_dir.display()
    );
    Ok(())
}

fn copy_dir_exact(src: &Path, dest: &Path) -> Result<()> {
    if !src.is_dir() {
        bail!("required asset directory missing: {}", src.display());
    }
    if dest.exists() {
        fs::remove_dir_all(dest).with_context(|| format!("removing {}", dest.display()))?;
    }
    copy_dir_all(src, dest)
}

fn copy_dir_all(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry.with_context(|| format!("reading {}", src.display()))?;
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        let metadata = entry
            .metadata()
            .with_context(|| format!("reading metadata for {}", src_path.display()))?;
        if metadata.is_dir() {
            copy_dir_all(&src_path, &dest_path)?;
        } else if metadata.is_file() {
            fs::copy(&src_path, &dest_path).with_context(|| {
                format!("copying {} to {}", src_path.display(), dest_path.display())
            })?;
            fs::set_permissions(&dest_path, metadata.permissions())
                .with_context(|| format!("setting permissions on {}", dest_path.display()))?;
        }
    }
    Ok(())
}

/// resolve the key provider for this install. Returns (addr, port, own_project).
fn resolve_key_provider(
    o: &InstallOpts,
    platform: Platform,
    start: bool,
    layout: &InstallLayout,
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
    // TDX: run our own gramine provider from the installed static assets unless
    // the operator points at an external provider or build directory.
    let default_key_provider_src = layout.key_provider_dir();
    let src = match o.key_provider_src.as_deref() {
        Some(src) => PathBuf::from(src),
        None if !start
            || default_key_provider_src
                .join("docker-compose.yaml")
                .exists() =>
        {
            println!(
                "  [ok] using key provider source {}",
                default_key_provider_src.display()
            );
            default_key_provider_src
        }
        None => {
            bail!(
                "no key provider: pass --use-existing-key-provider ADDR:PORT, \
                 or --key-provider-src DIR to run our own"
            )
        }
    };
    let project = format!("dstack-kp-{}", o.key_provider_port);
    if !start {
        println!(
            "  [ok] key provider source {} selected (not started because --no-start was passed)",
            src.display()
        );
        return Ok(("127.0.0.1".to_string(), o.key_provider_port, None));
    }
    let status = tool("docker")
        .args(["compose", "-p", &project, "-f"])
        .arg(src.join("docker-compose.yaml"))
        .args(["up", "-d"])
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

fn os_image_digest_file(platform: Platform) -> &'static str {
    match platform {
        Platform::AmdSevSnp => "digest.sev.txt",
        Platform::Tdx => "digest.txt",
    }
}

/// read the measured OS-image hash from the guest image's platform-specific
/// digest file, used to pin which image apps may boot.
/// Returns None when there's no image selected or no readable digest.
fn resolve_os_image_hash(images: &str, image: Option<&str>, platform: Platform) -> Option<String> {
    let img = image?;
    let digest_file = os_image_digest_file(platform);
    let path = Path::new(images).join(img).join(digest_file);
    let hash = fs::read_to_string(path).ok()?.trim().to_string();
    (!hash.is_empty()).then_some(hash)
}

/// resolve the OS-image pin, failing CLOSED: in KMS mode a missing/empty
/// platform digest is a hard error (an unpinned app could boot any unmeasured
/// image and still get keys), unless the operator opts out with
/// `--allow-unpinned-image`. Returns Some(hash) to pin, or None when pinning
/// is deliberately off (`--no-kms`, or the explicit opt-out).
fn resolve_image_pin(o: &InstallOpts, images: &str, platform: Platform) -> Result<Option<String>> {
    let hash = resolve_os_image_hash(images, o.image.as_deref(), platform);
    match &hash {
        Some(h) => println!("  [ok] pinning app os image {h}"),
        None if o.no_kms => {}
        None if o.allow_unpinned_image => {
            println!("  [!]  app os image not pinned (--allow-unpinned-image) - apps' image is unchecked")
        }
        None => bail!(
            "no os-image pin: could not read {digest_file} for image {:?} under {images}. \
             {} apps must be pinned to the measured OS image before they can receive keys. \
             use --image/--image-path with an image that contains {digest_file}, or pass \
             --allow-unpinned-image to proceed unpinned (not recommended)",
            o.image.as_deref().unwrap_or("<none>"),
            platform.vmm_str(),
            digest_file = os_image_digest_file(platform),
        ),
    }
    Ok(hash)
}

fn resolve_kms_port(o: &InstallOpts, st: &State) -> Result<u16> {
    if o.no_kms {
        return Ok(0);
    }
    if let Some(p) = o.kms_port {
        return Ok(p);
    }
    if let Some(p) = state_kms_port(st) {
        return Ok(p);
    }
    ports::free_local_port()
}

fn state_kms_port(st: &State) -> Option<u16> {
    st.kms_url.rsplit(':').next().and_then(|s| s.parse().ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpPortCheck {
    what: &'static str,
    flag: &'static str,
    addr: String,
    port: u16,
    check_free: bool,
}

fn tcp_port_plan(
    o: &InstallOpts,
    st: &State,
    platform: Platform,
    bind: &str,
    client_url: &str,
    kms_port: u16,
    kms_owned: bool,
) -> Vec<TcpPortCheck> {
    let auth_owned =
        st.auth_port == o.auth_port && !st.auth_unit.is_empty() && unit_active(&st.auth_unit);
    let vmm_owned =
        st.client_url == client_url && !st.vmm_unit.is_empty() && unit_active(&st.vmm_unit);

    let mut ports = vec![
        TcpPortCheck {
            what: "dashboard",
            flag: "--dashboard-port",
            addr: bind.to_string(),
            port: o.dashboard_port,
            check_free: !vmm_owned,
        },
        TcpPortCheck {
            what: "auth webhook",
            flag: "--auth-port",
            addr: "127.0.0.1".to_string(),
            port: o.auth_port,
            check_free: !auth_owned,
        },
    ];
    if !o.no_kms {
        ports.push(TcpPortCheck {
            what: "kms",
            flag: "--kms-port",
            addr: "127.0.0.1".to_string(),
            port: kms_port,
            check_free: !kms_owned,
        });
    }
    if platform == Platform::Tdx && o.use_existing_key_provider.is_none() {
        let expected_project = format!("dstack-kp-{}", o.key_provider_port);
        let key_provider_owned = st.kp_own_project.as_deref() == Some(expected_project.as_str());
        ports.push(TcpPortCheck {
            what: "key provider",
            flag: "--key-provider-port",
            addr: "127.0.0.1".to_string(),
            port: o.key_provider_port,
            check_free: !key_provider_owned,
        });
    }
    ports
}

async fn kms_port_owned(st: &State, client_url: &str, kms_port: u16, no_kms: bool) -> bool {
    if no_kms
        || st.client_url != client_url
        || state_kms_port(st) != Some(kms_port)
        || st.vmm_unit.is_empty()
        || !unit_active(&st.vmm_unit)
    {
        return false;
    }
    let Some(kms_vm_id) = &st.kms_vm_id else {
        return false;
    };
    match Vmm::connect(client_url) {
        Ok(vmm) => vmm.has_vm(kms_vm_id).await,
        Err(_) => false,
    }
}

/// fail BEFORE any side effect if a port we need is already taken, so a clash
/// refuses cleanly instead of half-installing. CIDs auto-offset (see
/// `pick_cid_start`); ports are user-facing, so we refuse with guidance rather
/// than silently moving the address the operator will connect to.
fn preflight_ports(ports: &[TcpPortCheck]) -> Result<()> {
    for (idx, a) in ports.iter().enumerate() {
        for b in ports.iter().skip(idx + 1) {
            if a.port == b.port && listener_addrs_overlap(&a.addr, &b.addr) {
                bail!(
                    "{} and {} both use {}:{}; choose distinct ports",
                    a.flag,
                    b.flag,
                    common_listener_addr(&a.addr, &b.addr),
                    a.port
                );
            }
        }
    }
    for port in ports {
        if port.port == 0 {
            bail!("{} must be between 1 and 65535", port.flag);
        }
        if port.check_free && !ports::tcp_port_free(&port.addr, port.port) {
            bail!(
                "{} port {}:{} is already in use; pass {} <free-port>",
                port.what,
                port.addr,
                port.port,
                port.flag
            );
        }
    }
    Ok(())
}

fn listener_addrs_overlap(a: &str, b: &str) -> bool {
    a == b || a == "0.0.0.0" || b == "0.0.0.0" || a == "::" || b == "::"
}

fn common_listener_addr(a: &str, b: &str) -> String {
    if a == b {
        a.to_string()
    } else {
        format!("{a}/{b}")
    }
}

fn validate_instance(instance: &str) -> Result<()> {
    if instance.is_empty() {
        bail!("--instance must not be empty");
    }
    if !instance
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("--instance may contain only ascii letters, digits, '-', '_', and '.'");
    }
    Ok(())
}

fn validate_install_opts(o: &InstallOpts) -> Result<()> {
    if let Some(instance) = o.instance.as_deref() {
        validate_instance(instance)?;
    }
    if o.key_provider_port == 0 {
        bail!("--key-provider-port must be between 1 and 65535");
    }
    if !o.no_kms && host::other_vmm_host_api_ports().contains(&o.host_api_port) {
        bail!(
            "host-api vsock port {} is already reserved by another dstack-vmm; pass --host-api-port <free-port>",
            o.host_api_port
        );
    }
    Ok(())
}

/// poll the KMS `GetMeta` RPC (self-signed TLS) until it bootstraps.
async fn wait_kms_ready(port: u16, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if kms_get_meta_ok(port).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// is the KMS bootstrapped and answering on `port`? the KMS serves self-signed
/// RA-TLS we deliberately don't verify here (`danger_accept_invalid_certs`); but
/// require the request to succeed AND a parsed, non-empty `ca_cert` field — so an
/// error body or a partial response can't read as "ready". A real success here
/// also confirms it's our KMS bound to this exact port (port-verification).
async fn kms_get_meta_ok(port: u16) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(4))
        .build()
    else {
        return false;
    };
    let Ok(resp) = client
        .post(format!("https://127.0.0.1:{port}/prpc/KMS.GetMeta?json"))
        .body("{}")
        .send()
        .await
    else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }
    let Ok(v) = resp.json::<serde_json::Value>().await else {
        return false;
    };
    v.get("ca_cert")
        .and_then(|c| c.as_str())
        .map(|s| !s.is_empty())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_check(what: &'static str, flag: &'static str, port: u16) -> TcpPortCheck {
        TcpPortCheck {
            what,
            flag,
            addr: "127.0.0.1".to_string(),
            port,
            check_free: false,
        }
    }

    #[test]
    fn preflight_rejects_duplicate_requested_ports() {
        let checks = vec![
            tcp_check("dashboard", "--dashboard-port", 19080),
            tcp_check("kms", "--kms-port", 19080),
        ];
        let err = preflight_ports(&checks).unwrap_err().to_string();
        assert!(err.contains("--dashboard-port"));
        assert!(err.contains("--kms-port"));
    }

    #[test]
    fn preflight_rejects_zero_port() {
        let err = preflight_ports(&[tcp_check("kms", "--kms-port", 0)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("--kms-port"));
        assert!(err.contains("between 1 and 65535"));
    }

    #[test]
    fn instance_rejects_systemd_unsafe_characters() {
        for bad in ["", "a/b", "a b", "a%b"] {
            assert!(
                validate_instance(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
        validate_instance("dstack-a_1.2").unwrap();
    }
}
