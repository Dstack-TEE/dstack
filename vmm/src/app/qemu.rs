// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! QEMU related code
use crate::{
    app::Manifest,
    config::{CvmConfig, GatewayConfig, Networking, PasstNetworking, ProcessAnnotation, Protocol},
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
    shared_filenames::{
        APP_COMPOSE, ENCRYPTED_ENV, HOST_SHARED_DISK_LABEL, INSTANCE_INFO, USER_CONFIG,
    },
    AppCompose, KeyProviderKind,
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
    pub events: Vec<pb::GuestEvent>,
}

#[derive(Debug, Builder)]
pub struct VmConfig {
    pub manifest: Manifest,
    pub image: Image,
    pub cid: u32,
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

/// Create a FAT32 disk image from a directory
fn create_shared_disk(disk_path: impl AsRef<Path>, shared_dir: impl AsRef<Path>) -> Result<()> {
    use fatfs::{FileSystem, FormatVolumeOptions, FsOptions};
    use std::io::{Cursor, Seek, SeekFrom, Write};

    let disk_path = disk_path.as_ref();
    let shared_dir = shared_dir.as_ref();

    const DISK_SIZE: usize = 8 * 1024 * 1024;
    let mut disk_data = vec![0u8; DISK_SIZE];

    {
        let cursor = Cursor::new(&mut disk_data);
        let mut label_bytes = [b' '; 11];
        let label_str = HOST_SHARED_DISK_LABEL.as_bytes();
        let copy_len = label_str.len().min(11);
        label_bytes[..copy_len].copy_from_slice(&label_str[..copy_len]);
        let format_opts = FormatVolumeOptions::new()
            .fat_type(fatfs::FatType::Fat32)
            .volume_label(label_bytes);
        fatfs::format_volume(cursor, format_opts).context("Failed to format disk as FAT32")?;
    }

    // Open the formatted filesystem in memory and copy files
    {
        let mut cursor = Cursor::new(&mut disk_data);
        cursor
            .seek(SeekFrom::Start(0))
            .context("Failed to seek to start")?;
        let fs =
            FileSystem::new(cursor, FsOptions::new()).context("Failed to open FAT32 filesystem")?;
        let root_dir = fs.root_dir();

        // Copy all files from shared_dir to the FAT32 root
        for entry in fs::read_dir(shared_dir).context("Failed to read shared directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() {
                let filename = entry.file_name();
                let filename_str = filename.to_string_lossy();

                // Read source file
                let content = fs::read(&path)
                    .with_context(|| format!("Failed to read file {}", path.display()))?;

                // Write to FAT32 filesystem
                let mut fat_file = root_dir
                    .create_file(&filename_str)
                    .with_context(|| format!("Failed to create file {filename_str} in FAT32"))?;
                fat_file
                    .write_all(&content)
                    .with_context(|| format!("Failed to write file {filename_str} to FAT32"))?;
                fat_file.flush().context("Failed to flush FAT32 file")?;
            }
        }
    }

    fs::write(disk_path, &disk_data)
        .with_context(|| format!("Failed to write disk image to {}", disk_path.display()))?;

    Ok(())
}

impl VmInfo {
    pub fn to_pb(&self, gw: &GatewayConfig, brief: bool) -> pb::VmInfo {
        let workdir = VmWorkDir::new(&self.workdir);
        let vm_config = workdir.manifest();
        let custom_gateway_urls = vm_config
            .as_ref()
            .map(|c| c.gateway_urls.clone())
            .unwrap_or_default();
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
                let kms_urls = vm_config
                    .as_ref()
                    .map(|c| c.kms_urls.clone())
                    .unwrap_or_default();
                let no_tee = vm_config
                    .as_ref()
                    .map(|c| c.no_tee)
                    .unwrap_or(self.manifest.no_tee);
                let stopped = !workdir.started().unwrap_or(false);

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
                    gateway_urls: custom_gateway_urls.clone(),
                    stopped,
                    no_tee,
                })
            },
            app_url: self
                .gateway_enabled
                .then_some(self.instance_id.as_ref())
                .flatten()
                .map(|id| {
                    // Use custom gateway URL if available, otherwise fall back to global config
                    if let Some(custom_gw_url) = custom_gateway_urls.first() {
                        if let Ok(url) = url::Url::parse(custom_gw_url) {
                            let host = url.host_str().unwrap_or(&gw.base_domain);
                            let port = url.port().unwrap_or(443);
                            if port == 443 {
                                return format!("https://{id}-{}.{}", gw.agent_port, host);
                            } else {
                                return format!("https://{id}-{}.{}:{}", gw.agent_port, host, port);
                            }
                        }
                    }
                    // Fall back to global gateway config
                    if gw.port == 443 {
                        format!("https://{id}-{}.{}", gw.agent_port, gw.base_domain)
                    } else {
                        format!(
                            "https://{id}-{}.{}:{}",
                            gw.agent_port, gw.base_domain, gw.port
                        )
                    }
                }),
            app_id: self.manifest.app_id.clone(),
            instance_id: self.instance_id.as_deref().map(Into::into),
            exited_at: self.exited_at.clone(),
            events: self.events.clone(),
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
            events: self.state.events.clone().into(),
        }
    }
}

impl VmConfig {
    fn config_passt(&self, workdir: &VmWorkDir, netcfg: &PasstNetworking) -> Result<ProcessConfig> {
        let PasstNetworking {
            passt_exec,
            interface,
            address,
            netmask,
            gateway,
            dns,
            map_host_loopback,
            map_guest_addr,
            no_map_gw,
            ipv4_only,
        } = netcfg;

        let passt_socket = workdir.passt_socket();
        if passt_socket.exists() {
            fs_err::remove_file(&passt_socket).context("Failed to remove passt socket")?;
        }
        let passt_exec = if passt_exec.is_empty() {
            "passt"
        } else {
            passt_exec
        };

        let passt_log = workdir.passt_log();

        let mut passt_cmd = Command::new(passt_exec);
        passt_cmd.arg("--socket").arg(&passt_socket);
        passt_cmd.arg("--log-file").arg(&passt_log);

        if !interface.is_empty() {
            passt_cmd.arg("--interface").arg(interface);
        }
        if !address.is_empty() {
            passt_cmd.arg("--address").arg(address);
        }
        if !netmask.is_empty() {
            passt_cmd.arg("--netmask").arg(netmask);
        }
        if !gateway.is_empty() {
            passt_cmd.arg("--gateway").arg(gateway);
        }
        for dns in dns {
            passt_cmd.arg("--dns").arg(dns);
        }
        if !map_host_loopback.is_empty() {
            passt_cmd.arg("--map-host-loopback").arg(map_host_loopback);
        }
        if !map_guest_addr.is_empty() {
            passt_cmd.arg("--map-guest-addr").arg(map_guest_addr);
        }
        if *no_map_gw {
            passt_cmd.arg("--no-map-gw");
        }
        if *ipv4_only {
            passt_cmd.arg("--ipv4-only");
        }
        // Group port mappings by protocol
        let mut tcp_ports = Vec::new();
        let mut udp_ports = Vec::new();

        for pm in &self.manifest.port_map {
            let port_spec = format!("{}/{}:{}", pm.address, pm.from, pm.to);
            match pm.protocol {
                Protocol::Tcp => tcp_ports.push(port_spec),
                Protocol::Udp => udp_ports.push(port_spec),
            }
        }
        // Add TCP port forwarding — one --tcp-ports per spec to avoid
        // exceeding passt's single-argument parser limit.
        for spec in &tcp_ports {
            passt_cmd.arg("--tcp-ports").arg(spec);
        }
        // Add UDP port forwarding
        for spec in &udp_ports {
            passt_cmd.arg("--udp-ports").arg(spec);
        }
        passt_cmd.arg("-f").arg("-1");

        let args = passt_cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let stdout_path = workdir.passt_stdout();
        let stderr_path = workdir.passt_stderr();
        let note = ProcessAnnotation {
            kind: "passt".to_string(),
            live_for: Some(self.manifest.id.clone()),
        };
        let note = serde_json::to_string(&note)?;
        let process_config = ProcessConfig {
            id: format!("passt-{}", self.manifest.id),
            args,
            name: format!("passt-{}", self.manifest.name),
            command: passt_exec.to_string(),
            env: Default::default(),
            cwd: workdir.to_string_lossy().to_string(),
            stdout: stdout_path.to_string_lossy().to_string(),
            stderr: stderr_path.to_string_lossy().to_string(),
            pidfile: Default::default(),
            cid: None,
            note,
        };
        Ok(process_config)
    }

    pub fn config_qemu(
        &self,
        workdir: impl AsRef<Path>,
        cfg: &CvmConfig,
        gpus: &GpuConfig,
    ) -> Result<Vec<ProcessConfig>> {
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
        let app_compose = workdir.app_compose().context("Failed to get app compose")?;
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
        let mut processes = vec![];
        command
            .arg("-drive")
            .arg(format!("file={},if=none,id=hd1", hda_path.display()))
            .arg("-device")
            .arg("virtio-blk-pci,drive=hd1");
        let netdev = match &cfg.networking {
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
            Networking::Passt(netcfg) => {
                processes.push(
                    self.config_passt(&workdir, netcfg)
                        .context("Failed to configure passt")?,
                );
                format!(
                    "stream,id=net0,server=off,addr.type=unix,addr.path={}",
                    workdir.passt_socket().display()
                )
            }
            Networking::Custom(netcfg) => netcfg.netdev.clone(),
        };
        command.arg("-netdev").arg(netdev);
        command.arg("-device").arg("virtio-net-pci,netdev=net0");

        self.configure_machine(&mut command, &workdir, cfg, &app_compose)?;
        self.configure_smbios(&mut command, cfg);

        if matches!(app_compose.key_provider(), KeyProviderKind::Tpm) {
            let tpm_path = if Path::new("/dev/tpmrm0").exists() {
                "/dev/tpmrm0"
            } else if Path::new("/dev/tpm0").exists() {
                "/dev/tpm0"
            } else {
                bail!("TPM key provider requested but no TPM device found on host");
            };
            command
                .arg("-tpmdev")
                .arg(format!("passthrough,id=tpm0,path={tpm_path}"))
                .arg("-device")
                .arg("tpm-tis,tpmdev=tpm0");
        }

        command
            .arg("-device")
            .arg(format!("vhost-vsock-pci,guest-cid={}", self.cid));

        // Configure shared files delivery: either via disk or 9p
        match cfg.host_share_mode.as_str() {
            "9p" => {
                // Use 9p virtfs (default)
                let ro = if self.image.info.shared_ro {
                    "on"
                } else {
                    "off"
                };
                command.arg("-virtfs").arg(format!(
                    "local,path={},mount_tag=host-shared,readonly={ro},security_model=mapped,id=virtfs0",
                    shared_dir.display(),
                ));
            }
            "vvfat" => {
                command
                    .arg("-blockdev")
                    .arg(format!(
                        "driver=vvfat,node-name=vvfat0,read-only=on,dir={},label={}",
                        shared_dir.display(),
                        HOST_SHARED_DISK_LABEL
                    ))
                    .arg("-device")
                    .arg("virtio-blk-pci,drive=vvfat0");
            }
            "vhd" => {
                // Use a second virtual disk (hd2) to share files
                let shared_disk_path = workdir.shared_disk_path();
                if shared_disk_path.exists() {
                    fs::remove_file(&shared_disk_path).context("Failed to remove shared disk")?;
                }
                create_shared_disk(&shared_disk_path, &shared_dir)
                    .context("Failed to create shared disk")?;
                command
                    .arg("-drive")
                    .arg(format!(
                        "file={},if=none,id=hd2,format=raw,readonly=on",
                        shared_disk_path.display()
                    ))
                    .arg("-device")
                    .arg("virtio-blk-pci,drive=hd2");
            }
            _ => {
                bail!("Invalid host sharing mode: {}", cfg.host_share_mode);
            }
        }

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
        let note = ProcessAnnotation {
            kind: "cvm".to_string(),
            live_for: None,
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
        processes.push(process_config);

        Ok(processes)
    }

    fn configure_machine(
        &self,
        command: &mut Command,
        workdir: &VmWorkDir,
        cfg: &CvmConfig,
        app_compose: &AppCompose,
    ) -> Result<()> {
        if self.manifest.no_tee {
            command
                .arg("-machine")
                .arg("q35,kernel-irqchip=split,hpet=off");
            return Ok(());
        }

        command
            .arg("-machine")
            .arg("q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off");

        let img_ver = self.image.info.version_tuple().unwrap_or_default();
        let support_mr_config_id = img_ver >= (0, 5, 2);

        // Compute mrconfigid if needed
        let mrconfigid = if cfg.use_mrconfigid && support_mr_config_id {
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
            Some(BASE64_STANDARD.encode(mr_config.to_mr_config_id()))
        } else {
            None
        };

        // Build tdx-guest object with optional quote-generation-socket for kernel-level TSM support
        #[derive(Serialize)]
        struct QgsSocket {
            r#type: &'static str,
            cid: &'static str,
            port: String,
        }

        #[derive(Serialize)]
        struct TdxGuestObject {
            #[serde(rename = "qom-type")]
            qom_type: &'static str,
            id: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            mrconfigid: Option<String>,
            #[serde(
                rename = "quote-generation-socket",
                skip_serializing_if = "Option::is_none"
            )]
            quote_generation_socket: Option<QgsSocket>,
        }

        let tdx_object = TdxGuestObject {
            qom_type: "tdx-guest",
            id: "tdx",
            mrconfigid: mrconfigid.clone(),
            quote_generation_socket: cfg.qgs_port.map(|port| QgsSocket {
                r#type: "vsock",
                cid: "2",
                port: port.to_string(),
            }),
        };

        // Use JSON format when quote-generation-socket is needed, otherwise use simple format
        let tdx_object_arg =
            serde_json::to_string(&tdx_object).context("failed to serialize tdx-guest object")?;
        command.arg("-object").arg(tdx_object_arg);
        Ok(())
    }

    fn configure_smbios(&self, command: &mut Command, cfg: &CvmConfig) {
        let p = &cfg.product;

        fn cfg_if(ty: &mut Vec<String>, name: &str, v: &Option<String>) {
            if let Some(v) = v {
                ty.push(format!("{name}={v}"));
            }
        }

        let mut types = [const { Vec::new() }; 4];
        // SMBIOS type=0 (BIOS Information)
        cfg_if(&mut types[0], "vendor", &p.bios_vendor);
        cfg_if(&mut types[0], "version", &p.bios_version);
        cfg_if(&mut types[0], "date", &p.bios_date);
        cfg_if(&mut types[0], "release", &p.bios_release);
        // SMBIOS type=1 (System Information)
        cfg_if(&mut types[1], "manufacturer", &p.sys_vendor);
        cfg_if(&mut types[1], "product", &p.product_name);
        cfg_if(&mut types[1], "version", &p.product_version);
        cfg_if(&mut types[1], "serial", &p.product_serial);
        cfg_if(&mut types[1], "uuid", &p.product_uuid);
        cfg_if(&mut types[1], "family", &p.product_family);
        cfg_if(&mut types[1], "sku", &p.product_sku);
        // SMBIOS type=2 (Baseboard Information)
        cfg_if(&mut types[2], "manufacturer", &p.board_vendor);
        cfg_if(&mut types[2], "product", &p.board_name);
        cfg_if(&mut types[2], "version", &p.board_version);
        cfg_if(&mut types[2], "serial", &p.board_serial);
        cfg_if(&mut types[2], "asset", &p.board_asset_tag);
        // SMBIOS type=3 (Chassis Information)
        cfg_if(&mut types[3], "manufacturer", &p.chassis_vendor);
        cfg_if(&mut types[3], "version", &p.chassis_version);
        cfg_if(&mut types[3], "serial", &p.chassis_serial);
        cfg_if(&mut types[3], "asset", &p.chassis_asset_tag);

        for (i, t) in types.iter().enumerate() {
            if !t.is_empty() {
                command
                    .arg("-smbios")
                    .arg(format!("type={i},{}", t.join(",")));
            }
        }
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

    pub fn shared_disk_path(&self) -> PathBuf {
        self.workdir.join("shared.img")
    }

    pub fn qmp_socket(&self) -> PathBuf {
        self.workdir.join("qmp.sock")
    }

    pub fn passt_socket(&self) -> PathBuf {
        self.workdir.join("passt.sock")
    }

    pub fn passt_stdout(&self) -> PathBuf {
        self.workdir.join("passt.stdout")
    }

    pub fn passt_stderr(&self) -> PathBuf {
        self.workdir.join("passt.stderr")
    }

    pub fn passt_log(&self) -> PathBuf {
        self.workdir.join("passt.log")
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

    pub fn app_compose(&self) -> Result<AppCompose> {
        let compose_file = self.app_compose_path();
        let compose: AppCompose = serde_json::from_str(&fs::read_to_string(compose_file)?)?;
        Ok(compose)
    }
}
