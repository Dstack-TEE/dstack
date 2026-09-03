// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Ownership of the fabric manager's shared NVSwitch partition definition file.
//!
//! The NVIDIA fabric manager can only activate NVLink partitions that already
//! exist in its partition definition file, and it reads that file once, when it
//! starts. The built-in table hard-codes a fixed set of GPU groupings, so a
//! host that hands out arbitrary subsets of its free GPUs cannot express the
//! group a new CVM needs.
//!
//! When `[cvm.gpu.nvswitch] enabled` is set, dstack-vmm owns the file instead:
//! every VM start recomputes one partition per GPU-attached VM that is running
//! or starting, and then runs the operator's apply command so the fabric
//! manager picks the file up. Two properties keep that from disturbing tenants
//! that are already running:
//!
//! * A VM keeps the partition id it was assigned on its first start — the id is
//!   persisted with the rest of its VM state — so a rewrite never redefines a
//!   partition that a running VM sits on.
//! * The file is rewritten, and the apply command run, only when the set of
//!   partitions actually changed. Restarting a VM that is already in the table
//!   touches nothing.
//!
//! Activating a partition (`fmpm -a`) is deliberately left to the apply
//! command: the fabric manager's activation semantics differ between driver
//! releases and multitenancy modes, so the mapping from table to activation is
//! the operator's to define. The command receives the plan through the
//! environment (see [`Nvswitch::apply`]).

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, SystemTime},
};

use anyhow::{bail, Context, Result};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, MutexGuard};
use tracing::{info, warn};
use wait_timeout::ChildExt;

use crate::config::NvswitchConfig;

/// Partition sizes with a documented multicast-slot quota on B200/B300 systems
/// (8 GPUs get every slot, 4 GPUs up to 50%, 2 GPUs up to 25%, 1 GPU none).
/// Other sizes are still emitted, but their quota is undefined by NVIDIA.
const DOCUMENTED_PARTITION_SIZES: [usize; 4] = [1, 2, 4, 8];

/// One VM's claim on the fabric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FabricClaim {
    /// The VM holding the GPUs.
    pub vm_id: String,
    /// Fabric module ids of the GPUs attached to the VM.
    pub module_ids: BTreeSet<u32>,
    /// Partition id assigned by an earlier reconcile, if the VM has one.
    pub partition_id: Option<u32>,
}

/// A VM and the partition id it owns in the rendered table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedPartition {
    pub vm_id: String,
    pub partition_id: u32,
    pub module_ids: BTreeSet<u32>,
}

/// An entry of the fabric manager partition definition file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PartitionInfo {
    #[serde(rename = "partitionId")]
    partition_id: u32,
    #[serde(rename = "gpuModuleIds")]
    gpu_module_ids: Vec<u32>,
}

/// The fabric manager partition definition file.
///
/// The layout is NVIDIA's, not ours: `version`, `name` and `time` are
/// informational, and `partitionInfo` is the part the fabric manager acts on.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartitionTable {
    version: u32,
    name: String,
    time: String,
    #[serde(rename = "partitionInfo")]
    partition_info: Vec<PartitionInfo>,
}

#[derive(Debug)]
pub(crate) struct Nvswitch {
    config: NvswitchConfig,
    /// Serializes the read-plan-write-apply cycle across concurrent VM starts.
    /// Without it, a start that snapshotted the VM list first could drop the
    /// partition of a VM that started in the meantime.
    lock: Mutex<()>,
}

impl Nvswitch {
    /// Validate the configuration and build the manager.
    ///
    /// Rejects an incomplete `[cvm.gpu.nvswitch]` section at startup rather
    /// than at the first GPU deployment.
    pub(crate) fn new(config: &NvswitchConfig) -> Result<Self> {
        if config.enabled {
            if config.partition_file.as_os_str().is_empty() {
                bail!("cvm.gpu.nvswitch.partition_file is required when nvswitch is enabled");
            }
            if config.apply_command.is_empty() {
                bail!("cvm.gpu.nvswitch.apply_command is required when nvswitch is enabled");
            }
            if config.module_ids.is_empty() {
                bail!("cvm.gpu.nvswitch.module_ids is required when nvswitch is enabled");
            }
            let mut seen = BTreeMap::new();
            for (slot, module_id) in &config.module_ids {
                if let Some(other) = seen.insert(*module_id, slot) {
                    bail!("gpu module id {module_id} is mapped to both {other} and {slot}");
                }
            }
        }
        Ok(Self {
            config: config.clone(),
            lock: Mutex::new(()),
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// Hold the fabric lock for a whole reconcile cycle.
    pub(crate) async fn lock(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().await
    }

    /// The fabric module id of a GPU, by PCI address.
    pub(crate) fn module_id(&self, slot: &str) -> Result<u32> {
        let slot = normalize_slot(slot);
        self.config
            .module_ids
            .get(&slot)
            .copied()
            .with_context(|| format!("no cvm.gpu.nvswitch.module_ids entry for gpu {slot}"))
    }

    /// Every module id the host knows about, for VMs that take all GPUs.
    pub(crate) fn all_module_ids(&self) -> BTreeSet<u32> {
        self.config.module_ids.values().copied().collect()
    }

    /// Write the table and run the apply command, unless the partitions are
    /// already the ones on disk.
    ///
    /// The apply command is spawned with:
    ///
    /// * `DSTACK_NVSWITCH_PARTITION_FILE` — path of the file just written.
    /// * `DSTACK_NVSWITCH_PARTITION_IDS` — space-separated ids in the table.
    ///
    /// so a site script can restart the fabric manager and activate the
    /// partitions without dstack-vmm encoding either step.
    pub(crate) fn apply(&self, partitions: &[PlannedPartition]) -> Result<()> {
        let partition_info = render_partitions(partitions);
        if partition_info == current_partitions(&self.config.partition_file) {
            return Ok(());
        }
        let table = PartitionTable {
            version: 0,
            name: "dstack-vmm".to_string(),
            time: humantime::format_rfc3339_seconds(SystemTime::now()).to_string(),
            partition_info,
        };
        let path = &self.config.partition_file;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("failed to create partition file directory")?;
        }
        let body = serde_json::to_vec_pretty(&table).context("failed to serialize the table")?;
        safe_write::safe_write(path, &body).context("failed to write the partition file")?;
        info!(
            partitions = table.partition_info.len(),
            file = %path.display(),
            "rewrote the nvswitch partition table"
        );
        self.run_apply_command(&table)
    }

    fn run_apply_command(&self, table: &PartitionTable) -> Result<()> {
        let (program, args) = self
            .config
            .apply_command
            .split_first()
            .context("empty apply command")?;
        let ids = table
            .partition_info
            .iter()
            .map(|partition| partition.partition_id.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let timeout = Duration::from_millis(self.config.apply_timeout_ms);
        let mut child = Command::new(program)
            .args(args)
            .env(
                "DSTACK_NVSWITCH_PARTITION_FILE",
                &self.config.partition_file,
            )
            .env("DSTACK_NVSWITCH_PARTITION_IDS", &ids)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to execute {program}"))?;
        if child.wait_timeout(timeout)?.is_none() {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} timed out after {timeout:?}");
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            bail!("{program} failed: {}", error.trim());
        }
        info!(command = program, ids = %ids, "applied the nvswitch partition table");
        Ok(())
    }
}

/// Assign a partition id to every claim.
///
/// Claims that already carry an id keep it, so the entry a running VM depends
/// on is byte-identical across rewrites; the rest take the lowest free ids.
pub(crate) fn plan(mut claims: Vec<FabricClaim>) -> Result<Vec<PlannedPartition>> {
    claims.retain(|claim| !claim.module_ids.is_empty());
    // The caller iterates a hash map, so sort for a stable id assignment.
    claims.sort_by(|left, right| left.vm_id.cmp(&right.vm_id));

    let mut owner_of_module = BTreeMap::new();
    for claim in &claims {
        for module_id in &claim.module_ids {
            if let Some(other) = owner_of_module.insert(*module_id, &claim.vm_id) {
                bail!(
                    "gpu module {module_id} is claimed by both vm {other} and vm {}",
                    claim.vm_id
                );
            }
        }
    }

    let mut taken = BTreeSet::new();
    let mut planned = Vec::with_capacity(claims.len());
    for claim in &claims {
        let Some(partition_id) = claim.partition_id else {
            continue;
        };
        if !taken.insert(partition_id) {
            // Two VMs recorded the same id, which only happens if the state
            // files were tampered with or restored from another host. Drop the
            // duplicate into the second pass instead of emitting a table the
            // fabric manager would reject.
            warn!(
                vm_id = claim.vm_id,
                partition_id, "duplicate nvswitch partition id, reassigning"
            );
            continue;
        }
        planned.push(PlannedPartition {
            vm_id: claim.vm_id.clone(),
            partition_id,
            module_ids: claim.module_ids.clone(),
        });
    }

    let mut next_id = 0;
    for claim in &claims {
        if planned.iter().any(|entry| entry.vm_id == claim.vm_id) {
            continue;
        }
        while !taken.insert(next_id) {
            next_id += 1;
        }
        planned.push(PlannedPartition {
            vm_id: claim.vm_id.clone(),
            partition_id: next_id,
            module_ids: claim.module_ids.clone(),
        });
    }

    for partition in &planned {
        let size = partition.module_ids.len();
        if !DOCUMENTED_PARTITION_SIZES.contains(&size) {
            warn!(
                vm_id = partition.vm_id,
                size, "nvswitch partition size has no documented multicast slot quota"
            );
        }
    }

    planned.sort_by_key(|partition| partition.partition_id);
    Ok(planned)
}

/// Normalize a PCI address to the `0000:1b:00.0` form used as the module id key.
fn normalize_slot(slot: &str) -> String {
    if slot.matches(':').count() == 1 {
        format!("0000:{slot}")
    } else {
        slot.to_owned()
    }
}

fn render_partitions(partitions: &[PlannedPartition]) -> Vec<PartitionInfo> {
    partitions
        .iter()
        .map(|partition| PartitionInfo {
            partition_id: partition.partition_id,
            gpu_module_ids: partition.module_ids.iter().copied().collect(),
        })
        .collect()
}

/// The partitions currently on disk, or none when the file is missing or was
/// not written by us.
fn current_partitions(path: &Path) -> Vec<PartitionInfo> {
    let Ok(body) = fs::read(path) else {
        return Vec::new();
    };
    match serde_json::from_slice::<PartitionTable>(&body) {
        Ok(table) => table.partition_info,
        Err(err) => {
            warn!(
                file = %path.display(),
                "unreadable nvswitch partition table, rewriting it: {err:#}"
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(vm_id: &str, module_ids: &[u32], partition_id: Option<u32>) -> FabricClaim {
        FabricClaim {
            vm_id: vm_id.to_string(),
            module_ids: module_ids.iter().copied().collect(),
            partition_id,
        }
    }

    #[test]
    fn assigns_the_lowest_free_ids_to_new_vms() {
        let planned = plan(vec![
            claim("vm-b", &[3, 4], None),
            claim("vm-a", &[1, 2], None),
        ])
        .unwrap();
        assert_eq!(planned[0].vm_id, "vm-a");
        assert_eq!(planned[0].partition_id, 0);
        assert_eq!(planned[1].vm_id, "vm-b");
        assert_eq!(planned[1].partition_id, 1);
    }

    #[test]
    fn keeps_the_ids_of_running_vms() {
        let planned = plan(vec![
            claim("vm-running", &[5, 6], Some(0)),
            claim("vm-new", &[1, 2], None),
        ])
        .unwrap();
        let running = planned.iter().find(|p| p.vm_id == "vm-running").unwrap();
        let new = planned.iter().find(|p| p.vm_id == "vm-new").unwrap();
        assert_eq!(running.partition_id, 0);
        assert_eq!(new.partition_id, 1);
    }

    #[test]
    fn fills_the_hole_left_by_a_stopped_vm() {
        // vm-a stopped, so id 0 is free again while vm-b keeps id 1.
        let planned = plan(vec![
            claim("vm-b", &[3, 4], Some(1)),
            claim("vm-c", &[1, 2], None),
        ])
        .unwrap();
        assert_eq!(planned[0].vm_id, "vm-c");
        assert_eq!(planned[0].partition_id, 0);
        assert_eq!(planned[1].vm_id, "vm-b");
        assert_eq!(planned[1].partition_id, 1);
    }

    #[test]
    fn reassigns_a_duplicated_id() {
        let planned = plan(vec![
            claim("vm-a", &[1, 2], Some(3)),
            claim("vm-b", &[3, 4], Some(3)),
        ])
        .unwrap();
        assert_eq!(planned.len(), 2);
        let ids: BTreeSet<u32> = planned.iter().map(|p| p.partition_id).collect();
        assert_eq!(ids, BTreeSet::from([0, 3]));
    }

    #[test]
    fn rejects_two_vms_claiming_one_gpu() {
        let error = plan(vec![
            claim("vm-a", &[1, 2], None),
            claim("vm-b", &[2, 3], None),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("gpu module 2"), "{error}");
    }

    #[test]
    fn drops_vms_without_gpus() {
        let planned = plan(vec![claim("vm-a", &[], None), claim("vm-b", &[1], None)]).unwrap();
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].vm_id, "vm-b");
    }

    #[test]
    fn rejects_an_incomplete_config() {
        let config = NvswitchConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(Nvswitch::new(&config).is_err());
        let disabled = NvswitchConfig::default();
        assert!(Nvswitch::new(&disabled).is_ok());
    }

    #[test]
    fn rejects_a_module_id_shared_by_two_gpus() {
        let config = NvswitchConfig {
            enabled: true,
            partition_file: "/tmp/customPartition.json".into(),
            apply_command: vec!["true".to_string()],
            apply_timeout_ms: 1000,
            module_ids: BTreeMap::from([
                ("0000:1b:00.0".to_string(), 1),
                ("0000:1c:00.0".to_string(), 1),
            ]),
        };
        let error = Nvswitch::new(&config).unwrap_err();
        assert!(error.to_string().contains("module id 1"), "{error}");
    }

    #[test]
    fn looks_up_module_ids_by_short_or_full_pci_address() {
        let config = NvswitchConfig {
            enabled: true,
            partition_file: "/tmp/customPartition.json".into(),
            apply_command: vec!["true".to_string()],
            apply_timeout_ms: 1000,
            module_ids: BTreeMap::from([("0000:1b:00.0".to_string(), 7)]),
        };
        let nvswitch = Nvswitch::new(&config).unwrap();
        assert_eq!(nvswitch.module_id("1b:00.0").unwrap(), 7);
        assert_eq!(nvswitch.module_id("0000:1b:00.0").unwrap(), 7);
        assert!(nvswitch.module_id("0000:1c:00.0").is_err());
    }

    #[test]
    fn applies_only_when_the_partitions_changed() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("applied");
        let config = NvswitchConfig {
            enabled: true,
            partition_file: dir.path().join("customPartition.json"),
            apply_command: vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("echo x >> {}", marker.display()),
            ],
            apply_timeout_ms: 10_000,
            module_ids: BTreeMap::from([("0000:1b:00.0".to_string(), 1)]),
        };
        let nvswitch = Nvswitch::new(&config).unwrap();
        let partitions = plan(vec![claim("vm-a", &[1, 2], None)]).unwrap();

        nvswitch.apply(&partitions).unwrap();
        nvswitch.apply(&partitions).unwrap();
        assert_eq!(fs::read_to_string(&marker).unwrap().lines().count(), 1);

        let grown = plan(vec![
            claim("vm-a", &[1, 2], None),
            claim("vm-b", &[3], None),
        ])
        .unwrap();
        nvswitch.apply(&grown).unwrap();
        assert_eq!(fs::read_to_string(&marker).unwrap().lines().count(), 2);

        let table: serde_json::Value =
            serde_json::from_slice(&fs::read(&config.partition_file).unwrap()).unwrap();
        assert_eq!(table["partitionInfo"][0]["partitionId"], 0);
        assert_eq!(
            table["partitionInfo"][0]["gpuModuleIds"],
            serde_json::json!([1, 2])
        );
    }

    #[test]
    fn fails_the_start_when_the_apply_command_fails() {
        let dir = tempfile::tempdir().unwrap();
        let config = NvswitchConfig {
            enabled: true,
            partition_file: dir.path().join("customPartition.json"),
            apply_command: vec!["false".to_string()],
            apply_timeout_ms: 10_000,
            module_ids: BTreeMap::from([("0000:1b:00.0".to_string(), 1)]),
        };
        let nvswitch = Nvswitch::new(&config).unwrap();
        let partitions = plan(vec![claim("vm-a", &[1], None)]).unwrap();
        assert!(nvswitch.apply(&partitions).is_err());
    }
}
