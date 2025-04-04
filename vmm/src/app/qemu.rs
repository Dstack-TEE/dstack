//! QEMU related code
use crate::{
    app::Manifest,
    config::{CvmConfig, GatewayConfig, Networking, ProcessNote},
};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::Permissions,
    ops::Deref,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};

use super::{image::Image, VmState};
use anyhow::{bail, Context, Result};
use bon::Builder;
use dstack_types::shared_filenames::{APP_COMPOSE, ENCRYPTED_ENV, INSTANCE_INFO, USER_CONFIG};
use dstack_vmm_rpc as pb;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use supervisor_client::supervisor::{ProcessConfig, ProcessInfo};

#[derive(Debug, Deserialize)]
pub struct InstanceInfo {
    pub instance_id: String,
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
}

#[derive(Debug, Builder)]
pub struct VmConfig {
    pub manifest: Manifest,
    pub image: Image,
    pub cid: u32,
    pub networking: Networking,
    pub workdir: PathBuf,
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
    pub fn to_pb(&self, gw: &GatewayConfig) -> pb::VmInfo {
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
            configuration: Some(pb::VmConfiguration {
                name: self.manifest.name.clone(),
                image: self.manifest.image.clone(),
                compose_file: {
                    fs::read_to_string(workdir.app_compose_path()).unwrap_or_default()
                },
                encrypted_env: { fs::read(workdir.encrypted_env_path()).unwrap_or_default() },
                user_config: { fs::read_to_string(workdir.user_config_path()).unwrap_or_default() },
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
                gpus: self
                    .manifest
                    .gpus
                    .iter()
                    .map(|gpu| pb::GpuSpec {
                        product_id: gpu.product_id.clone(),
                        slot: gpu.slot.clone(),
                    })
                    .collect(),
            }),
            app_url: self.instance_id.as_ref().map(|id| {
                format!(
                    "https://{id}-{}.{}:{}",
                    gw.agent_port, gw.base_domain, gw.port
                )
            }),
            app_id: self.manifest.app_id.clone(),
            instance_id: self.instance_id.as_deref().map(Into::into),
            exited_at: self.exited_at.clone(),
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
        }
    }
}

impl VmConfig {
    pub fn config_qemu(
        &self,
        workdir: impl AsRef<Path>,
        cfg: &CvmConfig,
        devices: &[String],
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
        let smp = self.manifest.vcpu.max(1);
        let mut command = Command::new(qemu);
        command.arg("-accel").arg("kvm");
        command.arg("-cpu").arg("host");
        command.arg("-smp").arg(smp.to_string());
        command.arg("-m").arg(format!("{}M", self.manifest.memory));
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
        command.arg("-kernel").arg(&self.image.kernel);
        command.arg("-initrd").arg(&self.image.initrd);
        command
            .arg("-drive")
            .arg(format!("file={},if=none,id=hd0", hda_path.display()))
            .arg("-device")
            .arg("virtio-blk-pci,drive=hd0");
        if let Some(rootfs) = &self.image.rootfs {
            command.arg("-cdrom").arg(rootfs);
        }
        if let Some(bios) = &self.image.bios {
            command.arg("-bios").arg(bios);
        }
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
        command.arg("-object").arg("tdx-guest,id=tdx");
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
        // Add GPU support if there are any GPU devices
        if !devices.is_empty() {
            command
                .arg("-device")
                .arg("pcie-root-port,id=pci.1,bus=pcie.0");
            command
                .arg("-fw_cfg")
                .arg("name=opt/ovmf/X-PciMmio64,string=262144");

            // Add iommufd objects and vfio-pci devices for each GPU
            for (i, device) in devices.iter().enumerate() {
                command.arg("-object").arg(format!("iommufd,id=iommufd{i}"));
                command.arg("-device").arg(format!(
                    "vfio-pci,host={device},bus=pci.1,iommufd=iommufd{i}"
                ));
            }
        }

        // Add kernel command line
        if let Some(cmdline) = &self.image.info.cmdline {
            command.arg("-append").arg(cmdline);
        }

        // NUMA and hugepages configuration
        let mut numa_cpus = None;
        let memory = self.manifest.memory;

        // NUMA pinning if requested and we have exactly one GPU
        if pin_numa {
            // Get the NUMA node for the GPU
            let (numa_node, cpus) = find_numa(devices.first().cloned())?;
            // Apply hugepages configuration if enabled
            if hugepages {
                command
                    .arg("-numa")
                    .arg(format!("node,nodeid=0,cpus=0-{},memdev=mem0", smp - 1));
                command.arg("-object").arg(format!(
                "memory-backend-file,id=mem0,size={memory}M,mem-path=/dev/hugepages,share=on,prealloc=yes,host-nodes={numa_node},policy=bind",
                ));
            }
            numa_cpus = Some(cpus);
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
        let note = ProcessNote {
            devices: devices.to_vec(),
        };
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

fn find_numa(device: Option<String>) -> Result<(String, String)> {
    let numa_node = match device {
        Some(device) => {
            // Ensure the device string only contains valid hexadecimal characters and colons
            if !device
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
            {
                bail!("Invalid device string");
            }
            // Get the NUMA node for the device
            let numa_node_path = format!("/sys/bus/pci/devices/0000:{}/numa_node", device);
            fs::read_to_string(&numa_node_path)
                .with_context(|| format!("Failed to read NUMA node from {}", numa_node_path))?
                .trim()
                .to_string()
        }
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
}

impl VmWorkDir {
    pub fn instance_info(&self) -> Result<InstanceInfo> {
        let info_file = self.instance_info_path();
        let info: InstanceInfo = serde_json::from_slice(&fs::read(&info_file)?)?;
        Ok(info)
    }
}
