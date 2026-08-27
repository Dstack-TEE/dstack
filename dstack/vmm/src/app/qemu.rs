// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! QEMU launch preparation and command construction.
use super::{
    effective_vcpu_count,
    host_share::create_shared_disk,
    hugepage_numa_nodes,
    image::Image,
    mr_config::{snp_host_data, tdx_mr_config_id},
    network::{
        bridge_helper, mac_address_for_vm_index, needs_netd_interface, validate_resolved_networks,
        warn_if_vhost_net_missing,
    },
    pci_numa_node, round_up, GpuConfig, VmWorkDir,
};
use crate::{
    app::Manifest,
    config::{CvmConfig, CvmPlatform, Networking, NetworkingMode, ProcessAnnotation},
    netd::{tap_name, InterfaceIdentity},
    vm_launcher::{ChildCommand, LaunchSpec, OpenFile},
};
use anyhow::{bail, Context, Result};
use bon::Builder;
use dstack_types::shared_filenames::HOST_SHARED_DISK_LABEL;
use dstack_types::version::Version;
use fs_err as fs;
use nix::unistd::{Gid, Uid};
use serde::Serialize;
use std::collections::HashMap;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use supervisor_client::supervisor::ProcessConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AmdSevSnpLaunchParams {
    cbitpos: u32,
    reduced_phys_bits: u32,
}

fn parse_amd_sev_snp_qmp_capabilities(stdout: &[u8]) -> Result<AmdSevSnpLaunchParams> {
    let stdout = std::str::from_utf8(stdout).context("QMP output is not valid UTF-8")?;
    let mut qmp_error = None;
    for line in stdout.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(error) = value.get("error") {
            qmp_error = Some(error.to_string());
        }
        let Some(ret) = value.get("return") else {
            continue;
        };
        let Some(cbitpos) = ret.get("cbitpos").and_then(|value| value.as_u64()) else {
            continue;
        };
        let Some(reduced_phys_bits) = ret
            .get("reduced-phys-bits")
            .and_then(|value| value.as_u64())
        else {
            continue;
        };
        return Ok(AmdSevSnpLaunchParams {
            cbitpos: cbitpos
                .try_into()
                .context("QMP cbitpos does not fit in u32")?,
            reduced_phys_bits: reduced_phys_bits
                .try_into()
                .context("QMP reduced-phys-bits does not fit in u32")?,
        });
    }

    match qmp_error {
        Some(error) => bail!("QMP query-sev-capabilities failed: {error}"),
        None => bail!("QMP query-sev-capabilities did not return cbitpos/reduced-phys-bits"),
    }
}

fn detect_amd_sev_snp_qemu_capabilities(qemu_path: &Path) -> Result<AmdSevSnpLaunchParams> {
    // QEMU's reduced-phys-bits is not the same value as CPUID Fn8000_001F
    // EBX[11:6] on all hosts. Ask the exact QEMU binary that will launch the
    // guest for its SEV launch parameters.
    let mut child = Command::new(qemu_path)
        .args([
            "-machine",
            "none,accel=kvm",
            "-display",
            "none",
            "-nodefaults",
            "-qmp",
            "stdio",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "failed to start QEMU to query SEV capabilities: {}",
                qemu_path.display()
            )
        })?;

    let mut stdin = child
        .stdin
        .take()
        .context("failed to open QEMU QMP stdin")?;
    stdin
        .write_all(
            br#"{"execute":"qmp_capabilities"}
{"execute":"query-sev-capabilities"}
{"execute":"quit"}
"#,
        )
        .context("failed to write QMP query-sev-capabilities commands")?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .context("failed to wait for QEMU query-sev-capabilities")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "QEMU query-sev-capabilities exited with {}: {}",
            output.status,
            stderr.trim()
        );
    }

    parse_amd_sev_snp_qmp_capabilities(&output.stdout)
}

#[derive(Debug, Builder)]
pub struct VmConfig {
    pub manifest: Manifest,
    pub image: Image,
    pub cid: u32,
    pub workdir: PathBuf,
    pub gateway_enabled: bool,
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

fn on_off(enabled: bool) -> &'static str {
    if enabled {
        "on"
    } else {
        "off"
    }
}

fn virtio_pci_device(device: &str, snp: bool) -> String {
    if snp {
        format!("{device},disable-legacy=on,iommu_platform=true")
    } else {
        device.to_string()
    }
}

struct PreparedVolume {
    source: String,
}

/// First descriptor the per-VM launcher may hand to QEMU. Zero through two are
/// the standard streams.
const FIRST_INHERITED_FD: i32 = 3;

/// Descriptors the launcher opens for each macvtap NIC, one per queue pair.
///
/// Both the launcher's open list and the `-netdev` arguments derive from this
/// one layout, so they cannot disagree about which descriptor belongs to which
/// NIC.
fn macvtap_fd_layout(networks: &[Networking]) -> Vec<Vec<i32>> {
    let mut next_fd = FIRST_INHERITED_FD;
    networks
        .iter()
        .map(|network| {
            if network.nic.mode != NetworkingMode::Macvtap {
                return Vec::new();
            }
            (0..network.queue_pairs())
                .map(|_| {
                    let fd = next_fd;
                    next_fd += 1;
                    fd
                })
                .collect()
        })
        .collect()
}

struct PreparedQemuLaunch {
    workdir: VmWorkDir,
    platform: CvmPlatform,
    networks: Vec<Networking>,
    volumes: Vec<PreparedVolume>,
    hugepage_numa_nodes: Option<HashMap<String, u32>>,
    gpu_numa_nodes: HashMap<String, String>,
    numa_cpus: Option<String>,
    swtpm_socket: Option<PathBuf>,
    swtpm_path: Option<PathBuf>,
    tdx_mr_config_id: Option<String>,
    snp_host_data: Option<String>,
    snp_launch_params: Option<AmdSevSnpLaunchParams>,
}

impl PreparedQemuLaunch {
    fn prepare(
        vm: &VmConfig,
        workdir: impl AsRef<Path>,
        cfg: &CvmConfig,
        gpus: &GpuConfig,
        networks: &[Networking],
    ) -> Result<Self> {
        let workdir = VmWorkDir::new(workdir);
        prepare_data_disk(vm, &workdir)?;
        prepare_shared_dir(&workdir)?;
        let app_compose = workdir.app_compose().context("failed to get app compose")?;
        let platform = cfg.resolved_platform();
        let networks = networks.to_vec();
        validate_resolved_networks(&networks)?;
        warn_if_vhost_net_missing(&networks);
        let volumes = vm
            .manifest
            .volumes
            .iter()
            .map(|volume| PreparedVolume {
                source: volume.source.clone(),
            })
            .collect();

        let hugepage_numa_nodes = if vm.manifest.hugepages {
            Some(hugepage_numa_nodes(gpus)?)
        } else {
            None
        };
        let gpu_numa_nodes = if vm.manifest.hugepages {
            gpus.gpus
                .iter()
                .map(|gpu| Ok((gpu.slot.clone(), pci_numa_node(&gpu.slot)?)))
                .collect::<Result<_>>()?
        } else {
            HashMap::new()
        };
        let numa_cpus = if vm.manifest.pin_numa {
            let device = gpus.gpus.first().map(|gpu| gpu.slot.clone());
            Some(find_numa(device)?.1)
        } else {
            None
        };
        let (swtpm_socket, swtpm_path) = if vm.manifest.swtpm {
            let swtpm_path = which::which("swtpm")
                .context("tpm key provider requested but swtpm is not installed")?;
            let state_dir = workdir.swtpm_state_dir();
            fs::create_dir_all(&state_dir).context("failed to create swtpm state directory")?;
            let socket = workdir.swtpm_socket();
            if socket.exists() {
                fs::remove_file(&socket).context("failed to remove stale swtpm socket")?;
            }
            (Some(socket), Some(swtpm_path))
        } else {
            (None, None)
        };
        prepare_shared_disk(&workdir, cfg)?;

        let tee_enabled = !vm.manifest.no_tee;
        let tdx_mr_config_id = if tee_enabled
            && platform == CvmPlatform::Tdx
            && cfg.use_mrconfigid
            && vm.image.info.version().unwrap_or_default() >= Version::new(0, 5, 2)
        {
            Some(tdx_mr_config_id(&workdir, &app_compose)?)
        } else {
            None
        };
        let (snp_host_data, snp_launch_params) =
            if tee_enabled && platform == CvmPlatform::AmdSevSnp {
                (
                    Some(snp_host_data(&workdir)?),
                    Some(
                        detect_amd_sev_snp_qemu_capabilities(&cfg.qemu_path).context(
                            "failed to detect AMD SEV-SNP cbitpos/reduced-phys-bits from QEMU",
                        )?,
                    ),
                )
            } else {
                (None, None)
            };

        Ok(Self {
            workdir,
            platform,
            networks,
            volumes,
            hugepage_numa_nodes,
            gpu_numa_nodes,
            numa_cpus,
            swtpm_socket,
            swtpm_path,
            tdx_mr_config_id,
            snp_host_data,
            snp_launch_params,
        })
    }
}

fn prepare_data_disk(vm: &VmConfig, workdir: &VmWorkDir) -> Result<()> {
    let hda_path = workdir.hda_path();
    if !hda_path.exists() {
        create_hd(
            &hda_path,
            vm.image.hda.as_ref(),
            &format!("{}G", vm.manifest.disk_size),
        )?;
    }
    Ok(())
}

fn prepare_shared_dir(workdir: &VmWorkDir) -> Result<()> {
    let shared_dir = workdir.shared_dir();
    if !shared_dir.exists() {
        fs::create_dir_all(&shared_dir)?;
    }
    Ok(())
}

fn prepare_shared_disk(workdir: &VmWorkDir, cfg: &CvmConfig) -> Result<()> {
    if cfg.host_share_mode != "vhd" {
        return Ok(());
    }

    let shared_dir = workdir.shared_dir();
    let shared_disk_path = workdir.shared_disk_path();
    if shared_disk_path.exists() {
        fs::remove_file(&shared_disk_path).context("failed to remove shared disk")?;
    }
    create_shared_disk(&shared_disk_path, shared_dir).context("failed to create shared disk")
}

struct QemuCommandBuilder<'a> {
    vm: &'a VmConfig,
    cfg: &'a CvmConfig,
    gpus: &'a GpuConfig,
    prepared: &'a PreparedQemuLaunch,
}

impl VmConfig {
    pub fn config_qemu(
        &self,
        workdir: impl AsRef<Path>,
        cfg: &CvmConfig,
        gpus: &GpuConfig,
        networks: &[Networking],
    ) -> Result<Vec<ProcessConfig>> {
        let prepared = PreparedQemuLaunch::prepare(self, workdir, cfg, gpus, networks)?;
        let process = QemuCommandBuilder {
            vm: self,
            cfg,
            gpus,
            prepared: &prepared,
        }
        .build()?;
        let has_macvtap = prepared
            .networks
            .iter()
            .any(|network| network.nic.mode == NetworkingMode::Macvtap);
        let Some(socket) = prepared.swtpm_socket.as_deref() else {
            if has_macvtap {
                return self.wrap_launcher(&prepared, process, None, None);
            }
            return Ok(vec![process]);
        };
        let swtpm_path = prepared
            .swtpm_path
            .as_ref()
            .context("missing swtpm executable for configured socket")?;
        let (socket_uid, socket_gid) = (Uid::effective().as_raw(), Gid::effective().as_raw());

        let swtpm_args = vec![
            "socket".into(),
            "--tpm2".into(),
            "--tpmstate".into(),
            format!("dir={}", prepared.workdir.swtpm_state_dir().display()),
            "--ctrl".into(),
            format!(
                "type=unixio,path={},mode=0600,uid={socket_uid},gid={socket_gid}",
                socket.display()
            ),
            "--flags".into(),
            "not-need-init,startup-clear".into(),
        ];
        self.wrap_launcher(
            &prepared,
            process,
            Some(ChildCommand {
                command: swtpm_path.to_string_lossy().into_owned(),
                args: swtpm_args,
            }),
            Some(socket.to_path_buf()),
        )
    }

    fn wrap_launcher(
        &self,
        prepared: &PreparedQemuLaunch,
        process: ProcessConfig,
        swtpm: Option<ChildCommand>,
        swtpm_socket: Option<PathBuf>,
    ) -> Result<Vec<ProcessConfig>> {
        // Each queue pair is a separate open of the same macvtap character
        // device; the kernel attaches one tap queue per open.
        let open_files = prepared
            .networks
            .iter()
            .zip(macvtap_fd_layout(&prepared.networks))
            .flat_map(|(network, fds)| {
                fds.into_iter().map(|fd| OpenFile {
                    fd,
                    path: network.device.clone().into(),
                })
            })
            .collect();
        let spec = LaunchSpec {
            qemu: ChildCommand {
                command: process.command,
                args: process.args,
            },
            swtpm,
            swtpm_socket,
            open_files,
            startup_timeout_ms: 5_000,
            shutdown_timeout_ms: 10_000,
        };
        let spec_path = prepared.workdir.launch_spec_path();
        safe_write::safe_write(&spec_path, serde_json::to_vec_pretty(&spec)?)
            .context("failed to write VM launch specification")?;
        let executable =
            std::env::current_exe().context("failed to locate dstack-vmm executable")?;
        let launcher = ProcessConfig {
            id: self.manifest.id.clone(),
            name: self.manifest.name.clone(),
            command: executable.to_string_lossy().into_owned(),
            args: vec![
                "vm-launcher".into(),
                "--spec".into(),
                spec_path.to_string_lossy().into_owned(),
            ],
            env: process.env,
            cwd: process.cwd,
            stdout: process.stdout,
            stderr: process.stderr,
            pidfile: process.pidfile,
            cid: process.cid,
            note: process.note,
        };
        Ok(vec![launcher])
    }
}

impl QemuCommandBuilder<'_> {
    fn build(&self) -> Result<ProcessConfig> {
        let mut command = self.base_command();
        self.configure_rootfs(&mut command)?;
        self.configure_data_disk(&mut command);
        self.configure_volumes(&mut command);
        self.configure_networking(&mut command)?;
        self.vm.configure_smbios(&mut command, self.cfg);
        self.configure_tpm_and_vsock(&mut command);
        self.configure_host_share(&mut command)?;

        let (smp, mem) = self.configure_hugepage_memory(&mut command)?;
        self.vm
            .configure_machine(&mut command, self.cfg, self.prepared, mem)?;
        self.configure_gpus(&mut command)?;
        command.arg("-smp").arg(smp.to_string());
        command.arg("-m").arg(format!("{mem}M"));

        // SNP app identity is bound through HOST_DATA, so the measured cmdline
        // remains the image-provided cmdline.
        if let Some(cmdline) = &self.vm.image.info.cmdline {
            command.arg("-append").arg(cmdline);
        }
        self.process_config(command)
    }

    fn is_amd_sev_snp(&self) -> bool {
        self.prepared.platform == CvmPlatform::AmdSevSnp && !self.vm.manifest.no_tee
    }

    fn base_command(&self) -> Command {
        let workdir = &self.prepared.workdir;
        let mut command = Command::new(&self.cfg.qemu_path);
        command.arg("-accel").arg("kvm");
        command.arg("-cpu").arg(if self.is_amd_sev_snp() {
            "EPYC-v4"
        } else {
            "host"
        });
        command.arg("-nographic");
        command.arg("-nodefaults");
        // logappend=on stops QEMU from truncating the log when it opens the
        // chardev, which is what makes in-place rotation safe: the fd is
        // O_APPEND, so writes resume at the end of file after we truncate.
        // Without it QEMU keeps writing at its old offset and punches a sparse
        // hole instead, leaving the file as large as it was.
        command.arg("-chardev").arg(format!(
            "pty,id=com0,path={},logfile={},logappend=on",
            workdir.serial_pty().display(),
            workdir.serial_file().display()
        ));
        command.arg("-serial").arg("chardev:com0");
        if self.cfg.qmp_socket {
            command.arg("-qmp").arg(format!(
                "unix:{},server,wait=off",
                workdir.qmp_socket().display()
            ));
        }
        if let Some(bios) = self.vm.image.firmware(self.is_amd_sev_snp()) {
            command.arg("-bios").arg(bios);
        }
        command.arg("-kernel").arg(&self.vm.image.kernel);
        command.arg("-initrd").arg(&self.vm.image.initrd);
        if self.cfg.qemu_hotplug_off {
            command.args([
                "-global",
                "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off",
            ]);
        }
        if self.cfg.qemu_pci_hole64_size > 0 {
            command.args([
                "-global",
                &format!(
                    "q35-pcihost.pci-hole64-size=0x{:x}",
                    self.cfg.qemu_pci_hole64_size
                ),
            ]);
        }
        command
    }

    fn configure_rootfs(&self, command: &mut Command) -> Result<()> {
        let Some(rootfs) = &self.vm.image.rootfs else {
            return Ok(());
        };
        let extension = rootfs
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        match extension {
            // Images before 0.5.0 shipped an `.iso` rootfs booted via `-cdrom`,
            // with no dm-verity behind it. `make_sys_config` has rejected those
            // images since it started requiring >= 0.5.0, so that branch was
            // already unreachable; dropping it keeps the rejection explicit
            // instead of leaving a non-verity boot path one edit away.
            "verity" => {
                command.arg("-drive").arg(format!(
                    "file={},if=none,id=hd0,format=raw,readonly=on",
                    rootfs.display()
                ));
                command.arg("-device").arg(virtio_pci_device(
                    "virtio-blk-pci,drive=hd0",
                    self.is_amd_sev_snp(),
                ));
            }
            _ => bail!("Unsupported rootfs type: {extension}"),
        }
        Ok(())
    }

    fn configure_data_disk(&self, command: &mut Command) {
        command
            .arg("-drive")
            .arg(format!(
                "file={},if=none,id=hd1",
                self.prepared.workdir.hda_path().display()
            ))
            .arg("-device")
            .arg(virtio_pci_device(
                "virtio-blk-pci,drive=hd1",
                self.is_amd_sev_snp(),
            ));
    }

    fn configure_volumes(&self, command: &mut Command) {
        // Sources are host paths already validated by the VMM. Attach extra
        // volumes after the data disk and before networking, matching the
        // established device order.
        for (index, volume) in self.prepared.volumes.iter().enumerate() {
            let id = format!("vol{index}");
            let drive = format!(
                "file={},if=none,id={id},format=raw,readonly=on",
                volume.source
            );

            let device = format!("virtio-blk-pci,drive={id}");
            command
                .arg("-drive")
                .arg(drive)
                .arg("-device")
                .arg(virtio_pci_device(&device, self.is_amd_sev_snp()));
        }
    }

    fn configure_networking(&self, command: &mut Command) -> Result<()> {
        let macvtap_fds = macvtap_fd_layout(&self.prepared.networks);
        let hostfwd_index = self
            .prepared
            .networks
            .iter()
            .position(|networking| networking.nic.mode == NetworkingMode::User);
        for (index, networking) in self.prepared.networks.iter().enumerate() {
            let net_id = format!("net{index}");
            let mac = mac_address_for_vm_index(
                &self.vm.manifest.id,
                &networking.mac_prefix_bytes(),
                index,
            );
            let queues = networking.queue_pairs();
            let vhost = networking.vhost_enabled();
            let mut device = format!("virtio-net-pci,netdev={net_id},mac={mac}");
            if queues > 1 {
                // One vector per queue direction, plus config and control.
                device.push_str(&format!(",mq=on,vectors={}", 2 * queues + 2));
            }
            let net_device = virtio_pci_device(&device, self.is_amd_sev_snp());
            let netdev = match networking.nic.mode {
                NetworkingMode::User => {
                    // The user-mode backend has neither, so both are ignored
                    // here. A caller who *named* this mode and then asked for
                    // vhost or more than one queue pair is refused by the RPC;
                    // one who inherited it is not, and lands here.
                    let mut netdev = format!(
                        "user,id={net_id},net={},dhcpstart={},restrict={}",
                        networking.net,
                        networking.dhcp_start,
                        if networking.restrict { "yes" } else { "no" }
                    );
                    if hostfwd_index == Some(index) {
                        for mapping in &self.vm.manifest.port_map {
                            netdev.push_str(&format!(
                                ",hostfwd={}:{}:{}-:{}",
                                mapping.protocol.as_str(),
                                mapping.address,
                                mapping.from,
                                mapping.to
                            ));
                        }
                    }
                    netdev
                }
                NetworkingMode::Bridge => {
                    tracing::info!(
                        "bridge networking: mac={mac} bridge={} vhost={vhost} queues={queues}",
                        networking.nic.bridge
                    );
                    if needs_netd_interface(networking, self.cfg) {
                        // netd owns this TAP: libvirt filtering binds an
                        // nwfilter to it, and multiqueue needs the persistent
                        // IFF_MULTI_QUEUE device the bridge helper cannot make.
                        let tap = tap_name(&InterfaceIdentity {
                            instance_id: self.cfg.instance_id.clone(),
                            vm_id: self.vm.manifest.id.clone(),
                            nic_index: index,
                        });
                        let mut netdev = format!(
                            "tap,id={net_id},ifname={tap},script=no,downscript=no,vhost={}",
                            on_off(vhost)
                        );
                        if queues > 1 {
                            netdev.push_str(&format!(",queues={queues}"));
                        }
                        netdev
                    } else if let Some(helper) = vhost.then(|| bridge_helper(self.cfg)).flatten() {
                        // QEMU's `bridge` netdev has no vhost support, but the
                        // same setuid helper works behind a `tap` netdev, so
                        // the VMM still needs no network privileges.
                        format!(
                            "tap,id={net_id},br={},helper={helper},vhost=on",
                            networking.nic.bridge
                        )
                    } else if vhost {
                        // vhost is a node-wide setting, so a node whose helper
                        // sits somewhere unusual must keep booting VMs rather
                        // than lose every bridge NIC to a path lookup.
                        tracing::warn!(
                            "{net_id}: no qemu-bridge-helper found, falling back to the \
                             non-vhost bridge netdev. set cvm.qemu_bridge_helper to enable vhost"
                        );
                        format!("bridge,id={net_id},br={}", networking.nic.bridge)
                    } else {
                        format!("bridge,id={net_id},br={}", networking.nic.bridge)
                    }
                }
                NetworkingMode::Custom => {
                    if !networking.netdev.contains(&format!("id={net_id}")) {
                        bail!(
                            "custom networking netdev must contain id={net_id} for interface index {index}"
                        );
                    }
                    networking.netdev.clone()
                }
                NetworkingMode::Macvtap => {
                    if networking.device.is_empty() {
                        bail!("macvtap interface {index} has not been prepared by netd");
                    }
                    let fds = macvtap_fds
                        .get(index)
                        .filter(|fds| !fds.is_empty())
                        .with_context(|| {
                            format!("macvtap interface {index} has no launcher descriptors")
                        })?;
                    let selector = if fds.len() == 1 {
                        format!("fd={}", fds[0])
                    } else {
                        let fds = fds
                            .iter()
                            .map(|fd| fd.to_string())
                            .collect::<Vec<_>>()
                            .join(":");
                        format!("fds={fds}")
                    };
                    format!("tap,id={net_id},{selector},vhost={}", on_off(vhost))
                }
            };
            command.arg("-netdev").arg(netdev);
            command.arg("-device").arg(net_device);
        }
        Ok(())
    }

    fn configure_tpm_and_vsock(&self, command: &mut Command) {
        if let Some(socket) = &self.prepared.swtpm_socket {
            command
                .arg("-chardev")
                .arg(format!("socket,id=chrtpm,path={}", socket.display()))
                .arg("-tpmdev")
                .arg("emulator,id=tpm0,chardev=chrtpm")
                .arg("-device")
                .arg("tpm-tis,tpmdev=tpm0");
        }
        command.arg("-device").arg(virtio_pci_device(
            &format!("vhost-vsock-pci,guest-cid={}", self.vm.cid),
            self.is_amd_sev_snp(),
        ));
    }

    fn configure_host_share(&self, command: &mut Command) -> Result<()> {
        let workdir = &self.prepared.workdir;
        match self.cfg.host_share_mode.as_str() {
            "9p" => {
                let read_only = if self.vm.image.info.shared_ro {
                    "on"
                } else {
                    "off"
                };
                command.arg("-virtfs").arg(format!(
                    "local,path={},mount_tag=host-shared,readonly={read_only},security_model=mapped,id=virtfs0",
                    workdir.shared_dir().display(),
                ));
            }
            "vvfat" => {
                command
                    .arg("-blockdev")
                    .arg(format!(
                        "driver=vvfat,node-name=vvfat0,read-only=on,dir={},label={}",
                        workdir.shared_dir().display(),
                        HOST_SHARED_DISK_LABEL
                    ))
                    .arg("-device")
                    .arg(virtio_pci_device(
                        "virtio-blk-pci,drive=vvfat0",
                        self.is_amd_sev_snp(),
                    ));
            }
            "vhd" => {
                command
                    .arg("-drive")
                    .arg(format!(
                        "file={},if=none,id=hd2,format=raw,readonly=on",
                        workdir.shared_disk_path().display()
                    ))
                    .arg("-device")
                    .arg(virtio_pci_device(
                        "virtio-blk-pci,drive=hd2",
                        self.is_amd_sev_snp(),
                    ));
            }
            _ => bail!("Invalid host sharing mode: {}", self.cfg.host_share_mode),
        }
        Ok(())
    }

    fn configure_hugepage_memory(&self, command: &mut Command) -> Result<(u32, u32)> {
        let numa_nodes = self.prepared.hugepage_numa_nodes.as_ref();
        let smp = effective_vcpu_count(
            self.vm.manifest.vcpu,
            numa_nodes.map(|nodes| nodes.len() as u32),
        );
        if !self.vm.manifest.hugepages {
            return Ok((smp, self.vm.manifest.memory));
        }

        let numa_nodes = numa_nodes
            .context("hugepage NUMA nodes should be computed during launch preparation")?;
        let numa_count = numa_nodes.len() as u32;
        let memory_gib = round_up(self.vm.manifest.memory / 1024, numa_count);
        let vcpus_per_node = smp / numa_count;
        let memory_per_node = memory_gib / numa_count;
        let mut bus_number = 5_u32;
        for (index, (node, device_count)) in numa_nodes.iter().enumerate() {
            let index = index as u32;
            let cpu_start = index * vcpus_per_node;
            let cpu_end = (index + 1) * vcpus_per_node - 1;
            command.arg("-numa").arg(format!(
                "node,nodeid={index},cpus={cpu_start}-{cpu_end},memdev=mem{index}",
            ));
            command.arg("-object").arg(format!(
                "memory-backend-file,id=mem{index},size={memory_per_node}G,mem-path=/dev/hugepages,share=on,prealloc=yes,host-nodes={node},policy=bind",
            ));
            let address = 0xa + index;
            command.arg("-device").arg(format!(
                "pxb-pcie,id=pcie.node{node},bus=pcie.0,addr={address},numa_node={index},bus_nr={bus_number}",
            ));
            bus_number += device_count + 1;
        }
        Ok((smp, memory_gib * 1024))
    }

    fn configure_gpus(&self, command: &mut Command) -> Result<()> {
        if self.gpus.gpus.is_empty() {
            return Ok(());
        }
        command.arg("-object").arg("iommufd,id=iommufd0");
        let mut device_number = 1;
        for device in &self.gpus.gpus {
            let slot = &device.slot;
            let bus = if self.vm.manifest.hugepages {
                let node = self
                    .prepared
                    .gpu_numa_nodes
                    .get(slot)
                    .context("gpu NUMA node should be computed during launch preparation")?;
                format!("pcie.node{node}")
            } else {
                "pcie.0".into()
            };
            command.arg("-device").arg(format!(
                "pcie-root-port,id=pci.{device_number},bus={bus},chassis={device_number}",
            ));
            command.arg("-device").arg(format!(
                "vfio-pci,host={slot},bus=pci.{device_number},iommufd=iommufd0",
            ));
            device_number += 1;
        }
        for bridge in &self.gpus.bridges {
            let slot = &bridge.slot;
            command.arg("-device").arg(format!(
                "pcie-root-port,id=pci.{device_number},bus=pcie.0,chassis={device_number}",
            ));
            command.arg("-device").arg(format!(
                "vfio-pci,host={slot},bus=pci.{device_number},iommufd=iommufd0",
            ));
            device_number += 1;
        }
        Ok(())
    }

    fn process_config(&self, command: Command) -> Result<ProcessConfig> {
        let workdir = &self.prepared.workdir;
        let mut arguments = vec![self.cfg.qemu_path.to_string_lossy().to_string()];
        arguments.extend(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().to_string()),
        );
        if let Some(cpus) = &self.prepared.numa_cpus {
            arguments.splice(0..0, ["taskset", "-c", cpus].into_iter().map(String::from));
        }

        let command = arguments.remove(0);
        let note = serde_json::to_string(&ProcessAnnotation {
            kind: "cvm".to_string(),
            live_for: None,
            // Recorded on the process rather than tracked in VMM memory, so it
            // survives a VMM restart and describes the QEMU that is actually
            // running. The vm-launcher wrapper copies this note verbatim, so
            // TPM-backed VMs carry it too.
            serial_logappend: true,
        })?;
        Ok(ProcessConfig {
            id: self.vm.manifest.id.clone(),
            args: arguments,
            name: self.vm.manifest.name.clone(),
            command,
            env: Default::default(),
            cwd: workdir.path().to_string_lossy().to_string(),
            stdout: workdir.stdout_file().to_string_lossy().to_string(),
            stderr: workdir.stderr_file().to_string_lossy().to_string(),
            pidfile: workdir.pid_file().to_string_lossy().to_string(),
            cid: Some(self.vm.cid),
            note,
        })
    }
}
impl VmConfig {
    fn configure_machine(
        &self,
        command: &mut Command,
        cfg: &CvmConfig,
        prepared: &PreparedQemuLaunch,
        mem: u32,
    ) -> Result<()> {
        if self.manifest.no_tee {
            command
                .arg("-machine")
                .arg("q35,kernel-irqchip=split,hpet=off");
            return Ok(());
        }

        match prepared.platform {
            CvmPlatform::Tdx => {
                command
                    .arg("-machine")
                    .arg("q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off");
                self.configure_tdx_guest(command, cfg, prepared.tdx_mr_config_id.as_deref())?;
            }
            CvmPlatform::AmdSevSnp => {
                let host_data = prepared
                    .snp_host_data
                    .as_deref()
                    .context("snp host data should be computed during launch preparation")?;
                let launch_params = prepared.snp_launch_params.context(
                    "snp launch parameters should be detected during launch preparation",
                )?;
                self.configure_amd_sev_snp_guest(command, cfg, mem, host_data, launch_params);
            }
        }
        Ok(())
    }

    fn configure_tdx_guest(
        &self,
        command: &mut Command,
        cfg: &CvmConfig,
        mrconfigid: Option<&str>,
    ) -> Result<()> {
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
            mrconfigid: mrconfigid.map(str::to_string),
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

    fn configure_amd_sev_snp_guest(
        &self,
        command: &mut Command,
        cfg: &CvmConfig,
        mem: u32,
        host_data: &str,
        snp_params: AmdSevSnpLaunchParams,
    ) {
        command
            .arg("-object")
            .arg(amd_sev_snp_memory_backend_arg(mem));
        command.arg("-object").arg(format!(
            "sev-snp-guest,id=sev0,policy=0x30000,sev-device=/dev/sev,kernel-hashes=on,host-data={host_data},cbitpos={},reduced-phys-bits={}",
            snp_params.cbitpos, snp_params.reduced_phys_bits
        ));
        command.arg("-machine").arg(
            "q35,kernel-irqchip=split,confidential-guest-support=sev0,memory-backend=ram1,hpet=off",
        );
        if cfg.qgs_port.is_some() {
            tracing::warn!("qgs_port is ignored for amd sev-snp guests");
        }
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

fn amd_sev_snp_memory_backend_arg(mem: u32) -> String {
    format!("memory-backend-memfd,id=ram1,size={mem}M,share=true,prealloc=false")
}

fn find_numa(device: Option<String>) -> Result<(String, String)> {
    let numa_node = match device {
        Some(device) => pci_numa_node(&device)?,
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use rocket::figment::{
        providers::{Format, Toml},
        Figment,
    };

    use super::{
        amd_sev_snp_memory_backend_arg, macvtap_fd_layout, parse_amd_sev_snp_qmp_capabilities,
        virtio_pci_device, PreparedQemuLaunch, PreparedVolume, QemuCommandBuilder, VmConfig,
    };
    use crate::app::image::{Image, ImageInfo};
    use crate::app::{needs_swtpm, GpuConfig, GpuSpec, Manifest, PortMapping, VmVolume, VmWorkDir};
    use crate::config::{
        Config, CvmPlatform, NetworkFilterMode, Networking, NetworkingMode, NicNetworking,
        Protocol, DEFAULT_CONFIG,
    };
    use crate::netd::{tap_name, InterfaceIdentity};
    use dstack_types::{KeyProviderKind, TeeVariant};

    #[test]
    fn swtpm_is_omitted_when_simulator_provides_the_tpm() {
        for platform in [TeeVariant::DstackGcpTdx, TeeVariant::DstackAwsNitroTpm] {
            assert!(!needs_swtpm(KeyProviderKind::Tpm, Some(platform)));
            assert!(!needs_swtpm(KeyProviderKind::Kms, Some(platform)));
        }

        assert!(needs_swtpm(
            KeyProviderKind::Tpm,
            Some(TeeVariant::DstackTdx)
        ));
        assert!(needs_swtpm(KeyProviderKind::Tpm, None));
        assert!(!needs_swtpm(KeyProviderKind::Kms, None));
    }

    #[test]
    fn amd_sev_snp_memory_backend_arg_uses_passed_final_memory_size() {
        assert_eq!(
            amd_sev_snp_memory_backend_arg(4096),
            "memory-backend-memfd,id=ram1,size=4096M,share=true,prealloc=false"
        );
    }

    #[test]
    fn amd_sev_snp_qmp_capabilities_extracts_launch_params() {
        let stdout = br#"{"QMP":{"version":{"qemu":{"major":10,"minor":0,"micro":2}}}}
{"return":{}}
{"return":{"reduced-phys-bits":1,"cbitpos":51,"cert-chain":"ignored","pdh":"ignored","cpu0-id":"ignored"}}
{"return":{}}
"#;
        let params = parse_amd_sev_snp_qmp_capabilities(stdout).unwrap();
        assert_eq!(params.cbitpos, 51);
        assert_eq!(params.reduced_phys_bits, 1);
    }

    #[test]
    fn amd_sev_snp_uses_confidential_virtio_pci_options() {
        assert_eq!(
            virtio_pci_device("virtio-blk-pci,drive=hd0", true),
            "virtio-blk-pci,drive=hd0,disable-legacy=on,iommu_platform=true"
        );
        assert_eq!(
            virtio_pci_device("virtio-blk-pci,drive=hd0", false),
            "virtio-blk-pci,drive=hd0"
        );
    }

    /// Minimal launch fixture. Nothing it points at has to exist on disk; every
    /// test overrides the fields it asserts on.
    fn test_launch_fixture() -> (Config, VmConfig, PreparedQemuLaunch) {
        let mut config: Config = Figment::from(Toml::string(DEFAULT_CONFIG))
            .extract()
            .unwrap();
        config.cvm.platform = Some(CvmPlatform::Tdx);
        config.cvm.qemu_path = PathBuf::from("/not-installed/qemu-system-x86_64");
        config.cvm.qgs_port = None;

        let vm = VmConfig {
            manifest: Manifest {
                id: "vm-1".into(),
                name: "test-vm".into(),
                app_id: "app-1".into(),
                vcpu: 2,
                memory: 2048,
                disk_size: 10,
                image: "test-image".into(),
                port_map: vec![PortMapping {
                    address: "127.0.0.1".parse().unwrap(),
                    protocol: Protocol::Tcp,
                    from: 18080,
                    to: 8080,
                }],
                created_at_ms: 0,
                hugepages: false,
                pin_numa: false,
                gpus: None,
                kms_urls: vec![],
                gateway_urls: vec![],
                no_tee: true,
                simulated_tee: None,
                swtpm: false,
                networks: vec![],
                volumes: vec![VmVolume {
                    source: "/does-not-exist/volume.img".into(),
                }],
            },
            image: Image {
                info: ImageInfo {
                    cmdline: Some("console=hvc0".into()),
                    kernel: "kernel".into(),
                    initrd: "initrd".into(),
                    hda: None,
                    rootfs: None,
                    bios: None,
                    bios_sev: None,
                    rootfs_hash: None,
                    shared_ro: false,
                    version: "0.5.4".into(),
                    is_dev: false,
                    ovmf_variant: None,
                },
                initrd: PathBuf::from("/does-not-exist/initrd"),
                kernel: PathBuf::from("/does-not-exist/kernel"),
                hda: None,
                rootfs: None,
                bios: None,
                bios_sev: None,
                digest: None,
                tdx_measurement: None,
                sev_measurement: None,
                gcp_measurement: None,
                aws_measurement: None,
                aws_pcr_replay: None,
                gcp_tpm_replay: None,
            },
            cid: 100,
            workdir: PathBuf::from("/does-not-exist/vm-1"),
            gateway_enabled: false,
        };
        let prepared = PreparedQemuLaunch {
            workdir: VmWorkDir::new("/does-not-exist/vm-1"),
            platform: CvmPlatform::Tdx,
            networks: vec![config.cvm.networking.clone(), config.cvm.networking.clone()],
            volumes: vec![PreparedVolume {
                source: "/does-not-exist/volume.img".into(),
            }],
            hugepage_numa_nodes: None,
            gpu_numa_nodes: HashMap::new(),
            numa_cpus: None,
            swtpm_socket: None,
            swtpm_path: None,
            tdx_mr_config_id: None,
            snp_host_data: None,
            snp_launch_params: None,
        };
        (config, vm, prepared)
    }

    /// Builds the `-netdev`/`-device` pairs for one NIC layout.
    fn net_args(config: &Config, networks: Vec<Networking>) -> Vec<String> {
        let (_, vm, mut prepared) = test_launch_fixture();
        prepared.networks = networks;
        let process = QemuCommandBuilder {
            vm: &vm,
            cfg: &config.cvm,
            gpus: &GpuConfig::default(),
            prepared: &prepared,
        }
        .build()
        .unwrap();
        process
            .args
            .windows(2)
            .filter(|args| args[0] == "-netdev" || args[0] == "-device")
            .map(|args| args[1].clone())
            .collect()
    }

    fn bridge_network(config: &Config) -> Networking {
        let mut networking = config.cvm.networking.clone();
        networking.nic.mode = NetworkingMode::Bridge;
        networking.nic.bridge = "br0".into();
        // The vhost tests below are about what an opted-in node builds; the
        // shipped default leaves it off.
        networking.nic.vhost = Some(true);
        networking
    }

    #[test]
    fn bridge_vhost_uses_the_bridge_helper_behind_a_tap_netdev() {
        // QEMU's `bridge` netdev has no vhost support at all, so enabling the
        // kernel data plane has to switch netdev types while keeping the same
        // unprivileged setuid helper.
        let (mut config, ..) = test_launch_fixture();
        config.cvm.qemu_bridge_helper = "/usr/lib/qemu/qemu-bridge-helper".into();
        let args = net_args(&config, vec![bridge_network(&config)]);
        assert!(args.contains(
            &"tap,id=net0,br=br0,helper=/usr/lib/qemu/qemu-bridge-helper,vhost=on".to_string()
        ));
        // A single queue pair must keep the historical device line byte for byte.
        assert!(args.iter().any(
            |arg| arg.starts_with("virtio-net-pci,netdev=net0,mac=") && !arg.contains("mq=on")
        ));
    }

    #[test]
    fn a_missing_bridge_helper_is_reported_rather_than_guessed() {
        // Configured paths are trusted verbatim: QEMU execs them, and it need
        // not share this filesystem.
        assert_eq!(
            crate::app::network::find_bridge_helper("  /opt/qemu-bridge-helper ", &[]),
            Some("/opt/qemu-bridge-helper")
        );
        assert_eq!(
            crate::app::network::find_bridge_helper("", &["/nonexistent/a", "/nonexistent/b"]),
            None
        );
    }

    #[test]
    fn disabling_vhost_restores_the_legacy_bridge_netdev() {
        let (config, ..) = test_launch_fixture();
        let mut networking = bridge_network(&config);
        networking.nic.vhost = Some(false);
        let args = net_args(&config, vec![networking]);
        assert!(args.contains(&"bridge,id=net0,br=br0".to_string()));
    }

    #[test]
    fn multiqueue_bridge_uses_the_netd_tap_and_derives_vectors() {
        let (mut config, ..) = test_launch_fixture();
        config.cvm.instance_id = "vmm-a".into();
        let mut networking = bridge_network(&config);
        networking.nic.queues = Some(4);
        let args = net_args(&config, vec![networking]);
        let tap = tap_name(&InterfaceIdentity {
            instance_id: "vmm-a".into(),
            vm_id: "vm-1".into(),
            nic_index: 0,
        });
        assert!(args.contains(&format!(
            "tap,id=net0,ifname={tap},script=no,downscript=no,vhost=on,queues=4"
        )));
        // vectors = 2 per queue pair, plus config and control.
        assert!(args.iter().any(|arg| arg.contains("mq=on,vectors=10")));
    }

    #[test]
    fn macvtap_queues_take_one_inherited_descriptor_each() {
        let (config, ..) = test_launch_fixture();
        let mut first = config.cvm.networking.clone();
        first.nic.mode = NetworkingMode::Macvtap;
        first.nic.parent = "eth0".into();
        first.nic.vhost = Some(true);
        first.device = "/dev/tap7".into();
        first.nic.queues = Some(2);
        let mut second = first.clone();
        second.device = "/dev/tap9".into();
        second.nic.queues = Some(3);

        let networks = vec![first, second];
        let args = net_args(&config, networks.clone());
        assert!(args.contains(&"tap,id=net0,fds=3:4,vhost=on".to_string()));
        assert!(args.contains(&"tap,id=net1,fds=5:6:7,vhost=on".to_string()));

        // The launcher must open exactly those descriptors, in that order.
        let layout = macvtap_fd_layout(&networks);
        assert_eq!(layout, vec![vec![3, 4], vec![5, 6, 7]]);
    }

    #[test]
    fn macvtap_keeps_a_single_fd_argument_for_one_queue() {
        let (config, ..) = test_launch_fixture();
        let mut networking = config.cvm.networking.clone();
        networking.nic.mode = NetworkingMode::Macvtap;
        networking.nic.parent = "eth0".into();
        networking.nic.vhost = Some(true);
        networking.device = "/dev/tap7".into();
        let args = net_args(&config, vec![networking]);
        assert!(args.contains(&"tap,id=net0,fd=3,vhost=on".to_string()));
    }

    /// The operator owns a custom netdev string and the VMM cannot edit it, so
    /// the generated device line must never claim more queues than that string
    /// provides -- QEMU refuses the mismatch, from inside the per-VM launcher
    /// where the reason is hard to see.
    #[test]
    fn custom_netdev_keeps_its_string_and_stays_single_queue() {
        let (config, ..) = test_launch_fixture();
        let mut networking = config.cvm.networking.clone();
        networking.nic.mode = NetworkingMode::Custom;
        networking.netdev = "tap,id=net0,ifname=custom0,vhost=on,queues=8".into();
        // Even a queue count that reached the entry some other way is ignored.
        networking.nic.queues = Some(8);
        let args = net_args(&config, vec![networking]);
        assert!(args.contains(&"tap,id=net0,ifname=custom0,vhost=on,queues=8".to_string()));
        assert!(
            args.iter().all(|arg| !arg.contains("mq=on")),
            "custom mode must not generate a multiqueue device line: {args:?}"
        );
    }

    #[test]
    fn user_mode_ignores_vhost_and_keeps_its_netdev() {
        let (config, ..) = test_launch_fixture();
        let mut networking = config.cvm.networking.clone();
        networking.nic.mode = NetworkingMode::User;
        networking.nic.vhost = Some(true);
        let args = net_args(&config, vec![networking]);
        assert!(args
            .iter()
            .any(|arg| arg.starts_with("user,id=net0,") && !arg.contains("vhost")));
        assert!(args.iter().any(
            |arg| arg.starts_with("virtio-net-pci,netdev=net0,mac=") && !arg.contains("mq=on")
        ));
    }

    #[test]
    fn qemu_command_builder_does_not_require_prepared_paths_to_exist() {
        let (mut config, vm, mut prepared) = test_launch_fixture();

        let process = QemuCommandBuilder {
            vm: &vm,
            cfg: &config.cvm,
            gpus: &GpuConfig::default(),
            prepared: &prepared,
        }
        .build()
        .unwrap();

        assert_eq!(process.command, "/not-installed/qemu-system-x86_64");
        assert!(process
            .args
            .windows(2)
            .any(|args| args == ["-machine", "q35,kernel-irqchip=split,hpet=off"]));
        assert!(process
            .args
            .windows(2)
            .any(|args| args == ["-kernel", "/does-not-exist/kernel"]));
        assert!(process
            .args
            .windows(2)
            .any(|args| args == ["-append", "console=hvc0"]));
        assert!(process.args.windows(2).any(|args| {
            args == [
                "-drive",
                "file=/does-not-exist/volume.img,if=none,id=vol0,format=raw,readonly=on",
            ]
        }));
        assert!(process
            .args
            .iter()
            .any(|arg| { arg == "virtio-blk-pci,drive=vol0" }));
        let volume_position = process
            .args
            .iter()
            .position(|arg| arg.contains("id=vol0"))
            .unwrap();
        let network_position = process
            .args
            .iter()
            .position(|arg| arg == "-netdev")
            .unwrap();
        assert!(volume_position < network_position);
        let netdevs = process
            .args
            .windows(2)
            .filter(|args| args[0] == "-netdev")
            .map(|args| args[1].as_str())
            .collect::<Vec<_>>();
        assert_eq!(netdevs.len(), 2);
        assert!(netdevs[0].contains("user,id=net0"));
        assert!(netdevs[0].contains("hostfwd=tcp:127.0.0.1:18080-:8080"));
        assert!(netdevs[1].contains("user,id=net1"));
        assert!(!netdevs[1].contains("hostfwd="));
        assert!(process
            .args
            .iter()
            .any(|arg| arg.contains("virtio-net-pci,netdev=net0")));
        assert!(process
            .args
            .iter()
            .any(|arg| arg.contains("virtio-net-pci,netdev=net1")));

        for network in &mut prepared.networks {
            network.nic.mode = NetworkingMode::Bridge;
            network.nic.bridge = "br0".into();
            network.nic.vhost = Some(false);
        }
        let process = QemuCommandBuilder {
            vm: &vm,
            cfg: &config.cvm,
            gpus: &GpuConfig::default(),
            prepared: &prepared,
        }
        .build()
        .unwrap();
        assert!(process
            .args
            .iter()
            .any(|arg| arg == "bridge,id=net0,br=br0"));

        config.cvm.instance_id = "vmm-a".into();
        config.cvm.network_filter.mode = NetworkFilterMode::Libvirt;
        let process = QemuCommandBuilder {
            vm: &vm,
            cfg: &config.cvm,
            gpus: &GpuConfig::default(),
            prepared: &prepared,
        }
        .build()
        .unwrap();
        let expected_tap = tap_name(&InterfaceIdentity {
            instance_id: "vmm-a".into(),
            vm_id: "vm-1".into(),
            nic_index: 0,
        });
        assert!(process.args.iter().any(|arg| {
            arg == &format!("tap,id=net0,ifname={expected_tap},script=no,downscript=no,vhost=off")
        }));
        assert!(process
            .args
            .iter()
            .all(|arg| !arg.contains("mq=on") && !arg.contains("vectors=")));

        prepared.swtpm_socket = Some(PathBuf::from("/does-not-exist/vm-1/swtpm/swtpm.sock"));
        let process = QemuCommandBuilder {
            vm: &vm,
            cfg: &config.cvm,
            gpus: &GpuConfig::default(),
            prepared: &prepared,
        }
        .build()
        .unwrap();
        assert!(process.args.windows(2).any(|args| {
            args == [
                "-chardev",
                "socket,id=chrtpm,path=/does-not-exist/vm-1/swtpm/swtpm.sock",
            ]
        }));
        assert!(process
            .args
            .windows(2)
            .any(|args| args == ["-tpmdev", "emulator,id=tpm0,chardev=chrtpm"]));

        assert!(process
            .args
            .iter()
            .any(|arg| arg.starts_with("local,path=") && arg.contains("mount_tag=host-shared")));

        prepared.swtpm_socket = None;
        prepared.networks = vec![Networking {
            nic: NicNetworking {
                mode: NetworkingMode::Custom,
                ..NicNetworking::default()
            },
            netdev: "tap,id=wrong".into(),
            ..Networking::default()
        }];
        let error = QemuCommandBuilder {
            vm: &vm,
            cfg: &config.cvm,
            gpus: &GpuConfig::default(),
            prepared: &prepared,
        }
        .build()
        .unwrap_err();
        assert!(error.to_string().contains("must contain id=net0"));
        prepared.networks[0].netdev = "tap,id=net0,fd=3".into();
        QemuCommandBuilder {
            vm: &vm,
            cfg: &config.cvm,
            gpus: &GpuConfig::default(),
            prepared: &prepared,
        }
        .build()
        .unwrap();

        let gpu = GpuConfig {
            gpus: vec![GpuSpec {
                slot: "0000:02:00.0".into(),
            }],
            ..Default::default()
        };
        let process = QemuCommandBuilder {
            vm: &vm,
            cfg: &config.cvm,
            gpus: &gpu,
            prepared: &prepared,
        }
        .build()
        .unwrap();
        assert!(process.args.iter().any(|arg| arg == "iommufd,id=iommufd0"));
        assert!(process
            .args
            .iter()
            .any(|arg| arg.contains("vfio-pci,host=0000:02:00.0")));
    }
}
