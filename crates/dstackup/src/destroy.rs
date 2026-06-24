// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup destroy` — tear down what `install` started.

use crate::state::{read_state, state_path};
use crate::systemd::{remove_unit, systemctl, tool};
use anyhow::{Context, Result};
use dstack_cli_core::vmm::Vmm;
use std::fs;
use std::path::Path;

/// tear down what `install` started; idempotent. Keeps the prefix (configs +
/// KMS keys) unless `--purge`.
pub(crate) async fn cmd_destroy(prefix: &str, purge: bool) -> Result<()> {
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
