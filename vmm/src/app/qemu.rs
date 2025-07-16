//! QEMU related code
use crate::{
    app::Manifest,
    config::{CvmConfig, GatewayConfig, Networking},
};
use std::{collections::HashMap, os::unix::fs::PermissionsExt};
use std::{
    fs::Permissions,
    ops::Deref,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};

use super::{image::Image, GpuConfig, VmState};
use anyhow::{bail, Context, Result};
use base64::prelude::*;
use bon::Builder;
use dstack_types::{
    mr_config::MrConfig,
    shared_filenames::{APP_COMPOSE, ENCRYPTED_ENV, INSTANCE_INFO, USER_CONFIG},
    AppCompose,
};
use dstack_vmm_rpc as pb;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use supervisor_client::supervisor::{ProcessConfig, ProcessInfo};

#[derive(Debug, Deserialize)]
pub struct InstanceInfo {
    #[serde(default)]
    pub instance_id: String,
    #[serde(default, with = "hex_bytes")]
    pub app_id: Vec<u8>,
}

pub struct VmInfo {
    pub manifest: Manifest,
    pub workdir: PathBuf,
    pub status: &'static str,
    pub uptime: String,
    pub exited_at: Option<String>,
    pub instance_id: Option<String>,
    pub boot_progress: String,
    pub boot_error: String,
    pub shutdown_progress: String,
    pub image_version: String,
    pub gateway_enabled: bool,
}

#[derive(Debug, Builder)]
pub struct VmConfig {
    pub manifest: Manifest,
    pub image: Image,
    pub cid: u32,
    pub networking: Networking,
    pub workdir: PathBuf,
    pub gateway_enabled: bool,
}

#[derive(Deserialize, Serialize)]
pub struct State {
    started: bool,
}

fn create_hd(
    image_file: impl AsRef<Path>,
    backing_file: Option<impl AsRef<Path>>,
    size: &str,
) -> Result<()> {
    let mut command = Command::new("qemu-img");
    command.arg("create").arg("-f").arg("qcow2");
    if let Some(backing_file) = backing_file {
        command
            .arg("-o")
            .arg(format!("backing_file={}", backing_file.as_ref().display()));
        command.arg("-o").arg("backing_fmt=qcow2");
    }
    command.arg(image_file.as_ref());
    command.arg(size);
    let output = command.output()?;
    if !output.status.success() {
        bail!(
            "Failed to create disk: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

impl VmInfo {
    pub fn to_pb(&self, gw: &GatewayConfig, brief: bool) -> pb::VmInfo {
        let workdir = VmWorkDir::new(&self.workdir);
        pb::VmInfo {
            id: self.manifest.id.clone(),
            name: self.manifest.name.clone(),
            status: self.status.into(),
            uptime: self.uptime.clone(),
            boot_progress: self.boot_progress.clone(),
            boot_error: self.boot_error.clone(),
            shutdown_progress: self.shutdown_progress.clone(),
            image_version: self.image_version.clone(),
            configuration: if brief {
                None
            } else {
                let vm_config = workdir.manifest();
                let kms_urls = vm_config
                    .as_ref()
                    .map(|c| c.kms_urls.clone())
                    .unwrap_or_default();
                let gateway_urls = vm_config
                    .as_ref()
                    .map(|c| c.gateway_urls.clone())
                    .unwrap_or_default();

                Some(pb::VmConfiguration {
                    name: self.manifest.name.clone(),
                    image: self.manifest.image.clone(),
                    compose_file: {
                        fs::read_to_string(workdir.app_compose_path()).unwrap_or_default()
                    },
                    encrypted_env: { fs::read(workdir.encrypted_env_path()).unwrap_or_default() },
                    user_config: {
                        fs::read_to_string(workdir.user_config_path()).unwrap_or_default()
                    },
                    vcpu: self.manifest.vcpu,
                    memory: self.manifest.memory,
                    disk_size: self.manifest.disk_size,
                    ports: self
                        .manifest
                        .port_map
                        .iter()
                        .map(|pm| pb::PortMapping {
                            protocol: pm.protocol.as_str().into(),
                            host_address: pm.address.to_string(),
                            host_port: pm.from as u32,
                            vm_port: pm.to as u32,
                        })
                        .collect(),
                    app_id: Some(self.manifest.app_id.clone()),
                    hugepages: self.manifest.hugepages,
                    pin_numa: self.manifest.pin_numa,
                    gpus: self.manifest.gpus.as_ref().map(|g| pb::GpuConfig {
                        attach_mode: g.attach_mode.to_string(),
                        gpus: g
                            .gpus
                            .iter()
                            .map(|gpu| pb::GpuSpec {
                                slot: gpu.slot.clone(),
                            })
                            .collect(),
                    }),
                    kms_urls,
                    gateway_urls,
                })
            },
            app_url: self
                .gateway_enabled
                .then_some(self.instance_id.as_ref())
                .flatten()
                .map(|id| {
                    format!(
                        "https://{id}-{}.{}:{}",
                        gw.agent_port, gw.base_domain, gw.port
                    )
                }),
            app_id: self.manifest.app_id.clone(),
            instance_id: self.instance_id.as_deref().map(Into::into),
            exited_at: self.exited_at.clone(),
            backup_in_progress: workdir.backup_lock_file().exists(),
        }
    }
}

impl VmState {
    pub fn merged_info(&self, proc_state: Option<&ProcessInfo>, workdir: &VmWorkDir) -> VmInfo {
        fn truncate(d: Duration) -> Duration {
            Duration::from_secs(d.as_secs())
        }
        let is_running = match proc_state {
            Some(info) => info.state.status.is_running(),
            None => false,
        };
        let started = workdir.started().unwrap_or(false);
        let status = match (started, is_running) {
            (true, true) => "running",
            (true, false) => "exited",
            (false, true) => "stopping",
            (false, false) => "stopped",
        };

        fn display_ts(t: Option<&SystemTime>) -> String {
            match t {
                None => "never".into(),
                Some(t) => {
                    let ts = t.elapsed().unwrap_or(Duration::MAX);
                    humantime::format_duration(truncate(ts)).to_string()
                }
            }
        }
        let uptime = display_ts(proc_state.and_then(|info| info.state.started_at.as_ref()));
        let exited_at = display_ts(proc_state.and_then(|info| info.state.stopped_at.as_ref()));
        let instance_id = workdir.instance_info().ok().map(|info| info.instance_id);
        VmInfo {
            manifest: self.config.manifest.clone(),
            workdir: workdir.path().to_path_buf(),
            instance_id,
            status,
            uptime,
            exited_at: Some(exited_at),
            boot_progress: self.state.boot_progress.clone(),
            boot_error: self.state.boot_error.clone(),
            shutdown_progress: self.state.shutdown_progress.clone(),
            image_version: self.config.image.info.version.clone(),
            gateway_enabled: self.config.gateway_enabled,
        }
    }
}

impl VmConfig {
    pub fn config_qemu(
        &self,
        workdir: impl AsRef<Path>,
        cfg: &CvmConfig,
        gpus: &GpuConfig,
    ) -> Result<ProcessConfig> {
        let workdir = VmWorkDir::new(workdir);
        let serial_file = workdir.serial_file();
        let serial_pty = workdir.serial_pty();
        let shared_dir = workdir.shared_dir();
        let disk_size = format!("{}G", self.manifest.disk_size);
        let hda_path = workdir.hda_path();
        if !hda_path.exists() {
            create_hd(&hda_path, self.image.hda.as_ref(), &disk_size)?;
        }
        if !cfg.user.is_empty() {
            fs_err::set_permissions(&hda_path, Permissions::from_mode(0o660))?;
        }

        if !shared_dir.exists() {
            fs::create_dir_all(&shared_dir)?;
        }
        let qemu = &cfg.qemu_path;
        let mut smp = self.manifest.vcpu.max(1);
        let mut mem = self.manifest.memory;
        let mut command = Command::new(qemu);
        command.arg("-accel").arg("kvm");
        command.arg("-cpu").arg("host");
        command.arg("-nographic");
        command.arg("-nodefaults");
        command.arg("-chardev").arg(format!(
            "pty,id=com0,path={},logfile={}",
            serial_pty.display(),
            serial_file.display()
        ));
        command.arg("-serial").arg("chardev:com0");
        if cfg.qmp_socket {
            command.arg("-qmp").arg(format!(
                "unix:{},server,wait=off",
                workdir.qmp_socket().display()
            ));
        }
        if let Some(bios) = &self.image.bios {
            command.arg("-bios").arg(bios);
        }
        command.arg("-kernel").arg(&self.image.kernel);
        command.arg("-initrd").arg(&self.image.initrd);
        if cfg.qemu_hotplug_off {
            command.args([
                "-global",
                "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off",
            ]);
        }
        if cfg.qemu_pci_hole64_size > 0 {
            command.args([
                "-global",
                &format!(
                    "q35-pcihost.pci-hole64-size=0x{:x}",
                    cfg.qemu_pci_hole64_size
                ),
            ]);
        }
        if let Some(rootfs) = &self.image.rootfs {
            let ext = rootfs
                .extension()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default();
            match ext {
                "iso" => {
                    command.arg("-cdrom").arg(rootfs);
                }
                "verity" => {
                    command.arg("-drive").arg(format!(
                        "file={},if=none,id=hd0,format=raw,readonly=on",
                        rootfs.display()
                    ));
                    command.arg("-device").arg("virtio-blk-pci,drive=hd0");
                }
                _ => {
                    bail!("Unsupported rootfs type: {ext}");
                }
            }
        }
        command
            .arg("-drive")
            .arg(format!("file={},if=none,id=hd1", hda_path.display()))
            .arg("-device")
            .arg("virtio-blk-pci,drive=hd1");
        let netdev = match &self.networking {
            Networking::User(netcfg) => {
                let mut netdev = format!(
                    "user,id=net0,net={},dhcpstart={},restrict={}",
                    netcfg.net,
                    netcfg.dhcp_start,
                    if netcfg.restrict { "yes" } else { "no" }
                );
                for pm in &self.manifest.port_map {
                    netdev.push_str(&format!(
                        ",hostfwd={}:{}:{}-:{}",
                        pm.protocol.as_str(),
                        pm.address,
                        pm.from,
                        pm.to
                    ));
                }
                netdev
            }
            Networking::Custom(netcfg) => netcfg.netdev.clone(),
        };
        command.arg("-netdev").arg(netdev);
        command.arg("-device").arg("virtio-net-pci,netdev=net0");

        command
            .arg("-machine")
            .arg("q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off");

        let img_ver = self.image.info.version_tuple().unwrap_or_default();
        let support_mr_config_id = img_ver >= (0, 5, 2);
        let tdx_object = if cfg.use_mrconfigid && support_mr_config_id {
            let app_compose = workdir.app_compose().context("Failed to get app compose")?;
            let compose_hash = workdir
                .app_compose_hash()
                .context("Failed to get compose hash")?;
            let mr_config = if app_compose.key_provider_id.is_empty() {
                MrConfig::V1 {
                    compose_hash: &compose_hash,
                }
            } else {
                let instance_info = workdir
                    .instance_info()
                    .context("Failed to get instance info")?;
                let app_id = if instance_info.app_id.is_empty() {
                    &compose_hash[..20]
                } else {
                    &instance_info.app_id
                };

                let key_provider = app_compose.key_provider();
                let key_provider_id = &app_compose.key_provider_id;
                MrConfig::V2 {
                    compose_hash: &compose_hash,
                    app_id: &app_id.try_into().context("Invalid app ID")?,
                    key_provider,
                    key_provider_id,
                }
            };
            let mrconfigid = BASE64_STANDARD.encode(mr_config.to_mr_config_id());
            format!("tdx-guest,id=tdx,mrconfigid={mrconfigid}")
        } else {
            "tdx-guest,id=tdx".to_string()
        };
        command.arg("-object").arg(tdx_object);

        command
            .arg("-device")
            .arg(format!("vhost-vsock-pci,guest-cid={}", self.cid));

        let ro = if self.image.info.shared_ro {
            "on"
        } else {
            "off"
        };
        command.arg("-virtfs").arg(format!(
            "local,path={},mount_tag=host-shared,readonly={ro},security_model=mapped,id=virtfs0",
            shared_dir.display(),
        ));

        let hugepages = self.manifest.hugepages;
        let pin_numa = self.manifest.pin_numa;
        // Handle GPU configuration
        let mut dev_num = 1;
        let memory = self.manifest.memory;

        // Handle hugepages configuration
        if hugepages {
            // Create a map of NUMA nodes to count of GPUs on that node
            let mut numa_nodes = HashMap::new();

            for device in &gpus.gpus {
                let node = find_numa_node(&device.slot)?;
                *numa_nodes.entry(node).or_insert(0) += 1;
            }

            if numa_nodes.is_empty() {
                numa_nodes.insert("0".to_string(), 0);
            }

            let n_numa = numa_nodes.len() as u32;

            // Round up CPU cores and memory to multiple times of NUMA nodes
            let vcpu_count = round_up(smp, n_numa);
            let mem_gb = round_up(memory / 1024, n_numa);
            let vcpu_per_node = vcpu_count / n_numa;
            let mem_per_node = mem_gb / n_numa;

            mem = mem_gb * 1024;
            smp = vcpu_count;

            let mut bus_nr = 5_u32;

            // Configure NUMA nodes
            for (ind, (node, count)) in numa_nodes.into_iter().enumerate() {
                let ind = ind as u32;
                let cpu_start = ind * vcpu_per_node;
                let cpu_end = (ind + 1) * vcpu_per_node - 1;
                command.arg("-numa").arg(format!(
                    "node,nodeid={ind},cpus={cpu_start}-{cpu_end},memdev=mem{ind}",
                ));

                command.arg("-object").arg(format!(
                    "memory-backend-file,id=mem{ind},size={mem_per_node}G,mem-path=/dev/hugepages,share=on,prealloc=yes,host-nodes={node},policy=bind",
                ));

                let addr = 0xa + ind;
                command.arg("-device").arg(format!(
                    "pxb-pcie,id=pcie.node{node},bus=pcie.0,addr={addr},numa_node={ind},bus_nr={bus_nr}",
                ));
                bus_nr += count + 1;
            }
        }

        // Configure GPU devices
        if !gpus.gpus.is_empty() {
            // Add iommufd object
            command.arg("-object").arg("iommufd,id=iommufd0");

            if !hugepages {
                // Add each GPU
                for device in &gpus.gpus {
                    let slot = &device.slot;
                    command.arg("-device").arg(format!(
                        "pcie-root-port,id=pci.{dev_num},bus=pcie.0,chassis={dev_num}",
                    ));
                    command.arg("-device").arg(format!(
                        "vfio-pci,host={slot},bus=pci.{dev_num},iommufd=iommufd0",
                    ));

                    dev_num += 1;
                }
            } else {
                // Add each GPU with NUMA node awareness for hugepages configuration
                for device in &gpus.gpus {
                    let slot = &device.slot;
                    let node = find_numa_node(slot)?;
                    command.arg("-device").arg(format!(
                        "pcie-root-port,id=pci.{dev_num},bus=pcie.node{node},chassis={dev_num}",
                    ));
                    command.arg("-device").arg(format!(
                        "vfio-pci,host={slot},bus=pci.{dev_num},iommufd=iommufd0",
                    ));
                    dev_num += 1;
                }
            }

            // Add bridges (NVSwitches) if any
            if !gpus.bridges.is_empty() {
                for bridge in &gpus.bridges {
                    let slot = &bridge.slot;
                    command.arg("-device").arg(format!(
                        "pcie-root-port,id=pci.{dev_num},bus=pcie.0,chassis={dev_num}",
                    ));
                    command.arg("-device").arg(format!(
                        "vfio-pci,host={slot},bus=pci.{dev_num},iommufd=iommufd0",
                    ));
                    dev_num += 1;
                }
            }
        }
        command.arg("-smp").arg(smp.to_string());
        command.arg("-m").arg(format!("{}M", mem));

        // NUMA pinning if requested
        let mut numa_cpus = None;
        if pin_numa {
            if !gpus.gpus.is_empty() {
                let (_, cpus) = find_numa(Some(gpus.gpus[0].slot.clone()))?;
                numa_cpus = Some(cpus);
            } else {
                // Default to NUMA node 0 if no GPUs
                let (_, cpus) = find_numa(None)?;
                numa_cpus = Some(cpus);
            }
        }

        // Add kernel command line
        if let Some(cmdline) = &self.image.info.cmdline {
            command.arg("-append").arg(cmdline);
        }

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        let pidfile_path = workdir.pid_file();
        let stdout_path = workdir.stdout_file();
        let stderr_path = workdir.stderr_file();

        let workdir = workdir.path();

        let mut cmd_args = vec![];
        cmd_args.push(qemu.to_string_lossy().to_string());
        cmd_args.extend(args);

        // If we have NUMA pinning, we'll need to wrap the command with taskset
        if let Some(cpus) = numa_cpus {
            cmd_args.splice(0..0, ["taskset", "-c", &cpus].into_iter().map(|s| s.into()));
        }

        if !cfg.user.is_empty() {
            cmd_args.splice(
                0..0,
                ["sudo", "-u", &cfg.user].into_iter().map(|s| s.into()),
            );
        }

        let command = cmd_args.remove(0);
        let note = "{}".to_string();
        let note = serde_json::to_string(&note)?;
        let process_config = ProcessConfig {
            id: self.manifest.id.clone(),
            args: cmd_args,
            name: self.manifest.name.clone(),
            command,
            env: Default::default(),
            cwd: workdir.to_string_lossy().to_string(),
            stdout: stdout_path.to_string_lossy().to_string(),
            stderr: stderr_path.to_string_lossy().to_string(),
            pidfile: pidfile_path.to_string_lossy().to_string(),
            cid: Some(self.cid),
            note,
        };

        Ok(process_config)
    }
}

/// Round up a value to the nearest multiple of another value.
/// If the value is already a multiple, it remains unchanged.
fn round_up(value: u32, multiple: u32) -> u32 {
    if multiple <= 1 {
        return value;
    }

    let remainder = value % multiple;
    if remainder == 0 {
        return value;
    }

    value + (multiple - remainder)
}

/// Get the NUMA node associated with a PCI device.
fn find_numa_node(device: &str) -> Result<String> {
    // Ensure the device string only contains valid hexadecimal characters and colons
    if !device
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
    {
        bail!("Invalid device string");
    }
    // Get the NUMA node for the device
    let numa_node_path = format!("/sys/bus/pci/devices/0000:{}/numa_node", device);
    let numa_node = fs::read_to_string(&numa_node_path)
        .with_context(|| format!("Failed to read NUMA node from {}", numa_node_path))?
        .trim()
        .to_string();

    // If the NUMA node is -1, default to 0
    if numa_node == "-1" {
        return Ok("0".to_string());
    }

    Ok(numa_node)
}

fn find_numa(device: Option<String>) -> Result<(String, String)> {
    let numa_node = match device {
        Some(device) => find_numa_node(&device)?,
        None => "0".into(),
    };
    // Get the CPU list for this NUMA node
    let cpus_path = format!("/sys/devices/system/node/node{numa_node}/cpulist");
    let cpus = fs::read_to_string(&cpus_path)
        .with_context(|| format!("Failed to read CPU list from {}", cpus_path))?
        .trim()
        .to_string();
    Ok((numa_node, cpus))
}

pub struct VmWorkDir {
    workdir: PathBuf,
}

impl Deref for VmWorkDir {
    type Target = PathBuf;
    fn deref(&self) -> &Self::Target {
        &self.workdir
    }
}

impl AsRef<Path> for &VmWorkDir {
    fn as_ref(&self) -> &Path {
        self.workdir.as_ref()
    }
}

impl VmWorkDir {
    pub fn new(workdir: impl AsRef<Path>) -> Self {
        Self {
            workdir: workdir.as_ref().to_path_buf(),
        }
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.workdir.join("vm-manifest.json")
    }

    pub fn state_path(&self) -> PathBuf {
        self.workdir.join("vm-state.json")
    }

    pub fn manifest(&self) -> Result<Manifest> {
        let manifest_path = self.manifest_path();
        let manifest = fs::read_to_string(manifest_path).context("Failed to read manifest")?;
        let manifest: Manifest =
            serde_json::from_str(&manifest).context("Failed to parse manifest")?;
        Ok(manifest)
    }

    pub fn put_manifest(&self, manifest: &Manifest) -> Result<()> {
        fs::create_dir_all(&self.workdir).context("Failed to create workdir")?;
        let manifest_path = self.manifest_path();
        fs::write(manifest_path, serde_json::to_string(manifest)?)
            .context("Failed to write manifest")
    }

    pub fn started(&self) -> Result<bool> {
        let state_path = self.state_path();
        if !state_path.exists() {
            return Ok(false);
        }
        let state: State =
            serde_json::from_str(&fs::read_to_string(state_path).context("Failed to read state")?)
                .context("Failed to parse state")?;
        Ok(state.started)
    }

    pub fn set_started(&self, started: bool) -> Result<()> {
        let state_path = self.state_path();
        fs::write(state_path, serde_json::to_string(&State { started })?)
            .context("Failed to write state")
    }

    pub fn shared_dir(&self) -> PathBuf {
        self.workdir.join("shared")
    }

    pub fn app_compose_path(&self) -> PathBuf {
        self.shared_dir().join(APP_COMPOSE)
    }

    pub fn app_compose_hash(&self) -> Result<[u8; 32]> {
        use sha2::Digest;
        let compose_path = self.app_compose_path();
        let compose = fs::read(compose_path).context("Failed to read compose")?;
        Ok(sha2::Sha256::new_with_prefix(&compose).finalize().into())
    }

    pub fn user_config_path(&self) -> PathBuf {
        self.shared_dir().join(USER_CONFIG)
    }

    pub fn encrypted_env_path(&self) -> PathBuf {
        self.shared_dir().join(ENCRYPTED_ENV)
    }

    pub fn instance_info_path(&self) -> PathBuf {
        self.shared_dir().join(INSTANCE_INFO)
    }

    pub fn serial_file(&self) -> PathBuf {
        self.workdir.join("serial.log")
    }

    pub fn serial_pty(&self) -> PathBuf {
        self.workdir.join("serial.pty")
    }

    pub fn stdout_file(&self) -> PathBuf {
        self.workdir.join("stdout.log")
    }

    pub fn stderr_file(&self) -> PathBuf {
        self.workdir.join("stderr.log")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.workdir.join("qemu.pid")
    }

    pub fn hda_path(&self) -> PathBuf {
        self.workdir.join("hda.img")
    }

    pub fn qmp_socket(&self) -> PathBuf {
        self.workdir.join("qmp.sock")
    }

    pub fn path(&self) -> &Path {
        &self.workdir
    }

    pub fn backup_lock_file(&self) -> PathBuf {
        self.workdir.join("backup.lock")
    }
}

impl VmWorkDir {
    pub fn instance_info(&self) -> Result<InstanceInfo> {
        let info_file = self.instance_info_path();
        let info: InstanceInfo = serde_json::from_slice(&fs::read(&info_file)?)?;
        Ok(info)
    }

    pub fn app_compose(&self) -> Result<AppCompose> {
        let compose_file = self.app_compose_path();
        let compose: AppCompose = serde_json::from_str(&fs::read_to_string(compose_file)?)?;
        Ok(compose)
    }
}
