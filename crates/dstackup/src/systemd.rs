// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! systemd unit management + the sanitized external-tool spawner.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command as PCommand;

/// spawn an external tool (systemctl/docker/curl) with a sanitized `PATH`, so a
/// hijacked environment can't substitute a different binary while we run as root.
pub(crate) fn tool(bin: &str) -> PCommand {
    let mut c = PCommand::new(bin);
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

pub(crate) fn systemctl(args: &[&str]) -> bool {
    tool("systemctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// systemd unit name (no `.service` suffix): `dstack-<base>` or, with an
/// instance, `dstack-<base>-<instance>` (so a fresh install coexists with an
/// existing `dstack-vmm.service`).
pub(crate) fn unit_name(base: &str, instance: &Option<String>) -> String {
    match instance {
        Some(i) if !i.is_empty() => format!("dstack-{base}-{i}"),
        _ => format!("dstack-{base}"),
    }
}

pub(crate) fn unit_active(unit: &str) -> bool {
    systemctl(&["is-active", "--quiet", &format!("{unit}.service")])
}

/// write a unit file, reload systemd, and enable+start it (idempotent).
pub(crate) fn install_unit(unit: &str, contents: &str) -> Result<()> {
    let path = format!("/etc/systemd/system/{unit}.service");
    fs::write(&path, contents).with_context(|| format!("writing {path}"))?;
    systemctl(&["daemon-reload"]);
    if !systemctl(&["enable", "--now", &format!("{unit}.service")]) {
        bail!("failed to enable+start {unit}.service");
    }
    Ok(())
}

/// stop, disable, and remove a unit (idempotent — missing unit is fine).
pub(crate) fn remove_unit(unit: &str) {
    let svc = format!("{unit}.service");
    let _ = systemctl(&["disable", "--now", &svc]);
    let _ = fs::remove_file(format!("/etc/systemd/system/{svc}"));
}

pub(crate) fn auth_unit_file(bin: &str, allowlist: &Path, port: u16, prefix: &Path) -> String {
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

pub(crate) fn vmm_unit_file(bin: &str, config: &Path, prefix: &Path, auth_unit: &str) -> String {
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
