// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup destroy` — tear down what `install` started.

use crate::state::{read_state, state_path};
use crate::systemd::{remove_unit, systemctl, tool};
use anyhow::{Context, Result};
use dstack_cli_core::layout::InstallLayout;
use dstack_cli_core::vmm::Vmm;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// tear down what `install` started; idempotent. Keeps generated config, state,
/// and KMS keys unless `--purge`.
pub(crate) async fn cmd_destroy(prefix: Option<&str>, purge: bool) -> Result<()> {
    let layout = InstallLayout::new(prefix);
    layout.validate()?;
    println!("dstackup destroy ({})", layout.state_dir.display());
    match read_state(&layout.state_dir) {
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
            let _ = fs::remove_file(state_path(&layout.state_dir));
        }
        None => println!(
            "  no install state at {} (nothing running to stop)",
            layout.state_dir.display()
        ),
    }

    if purge {
        purge_layout(&layout)?;
    } else {
        println!(
            "  configs kept at {}; state + KMS keys kept at {} (use --purge to wipe)",
            layout.config_dir.display(),
            layout.state_dir.display()
        );
    }
    Ok(())
}

fn purge_layout(layout: &InstallLayout) -> Result<()> {
    for dir in [
        &layout.config_dir,
        &layout.state_dir,
        &layout.cache_dir,
        &layout.run_dir,
    ] {
        remove_dir_all_if_exists(dir)?;
    }

    if let Some(root) = &layout.root {
        remove_dir_all_if_exists(&layout.share_dir)?;
        remove_dir_all_if_exists(&layout.libexec_dir)?;

        for file in [
            layout.bin_dir.join("dstack"),
            layout.bin_dir.join("dstackup"),
        ] {
            remove_file_if_exists(&file)?;
        }

        for dir in [
            &layout.bin_dir,
            &layout.libexec_dir,
            &layout.share_dir,
            &layout.config_dir,
            &layout.state_dir,
            &layout.cache_dir,
            &layout.run_dir,
        ] {
            remove_empty_parents(dir, root)?;
        }
        remove_empty_dir(&layout.bin_dir)?;
        remove_empty_dir(root)?;
    }
    Ok(())
}

fn remove_dir_all_if_exists(dir: &Path) -> Result<()> {
    match fs::remove_dir_all(dir) {
        Ok(()) => {
            println!("  purged {}", dir.display());
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("purging {}", dir.display())),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            println!("  removed {}", path.display());
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

fn remove_empty_parents(path: &Path, stop_at: &Path) -> Result<()> {
    let mut current = path.parent().map(PathBuf::from);
    while let Some(dir) = current {
        if !dir.starts_with(stop_at) {
            break;
        }
        if dir == stop_at {
            break;
        }
        remove_empty_dir(&dir)?;
        current = dir.parent().map(PathBuf::from);
    }
    Ok(())
}

fn remove_empty_dir(dir: &Path) -> Result<()> {
    match fs::remove_dir(dir) {
        Ok(()) => {
            println!("  removed empty dir {}", dir.display());
            Ok(())
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("removing empty dir {}", dir.display())),
    }
}
