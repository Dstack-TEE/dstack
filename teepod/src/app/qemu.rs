//! QEMU related code
use crate::{
    app::Manifest,
    config::{GatewayConfig, Networking},
};
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};

use super::image::Image;
use anyhow::{Context, Result};
use bon::Builder;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use supervisor_client::supervisor::{ProcessConfig, ProcessInfo};
use teepod_rpc as pb;

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
}

#[derive(Debug)]
pub struct TdxConfig {
    /// Guest CID for vhost-vsock
    pub cid: u32,
}

#[derive(Debug, Builder)]
pub struct VmConfig {
    pub manifest: Manifest,
    pub image: Image,
    pub tdx_config: Option<TdxConfig>,
    pub networking: Networking,
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
    command.spawn()?.wait()?;
    Ok(())
}

impl VmInfo {
    pub fn to_pb(&self, gw: &GatewayConfig) -> pb::VmInfo {
        let workdir = VmWorkDir::new(&self.workdir);
        pb::VmInfo {
            id: self.manifest.id.as_str().into(),
            name: self.manifest.name.as_str().into(),
            status: self.status.into(),
            uptime: self.uptime.as_str().into(),
            configuration: Some(pb::VmConfiguration {
                name: self.manifest.name.as_str().into(),
                image: self.manifest.image.as_str().into(),
                compose_file: {
                    fs::read_to_string(workdir.app_compose_path()).unwrap_or_default()
                },
                encrypted_env: { fs::read(workdir.encrypted_env_path()).unwrap_or_default() },
                vcpu: self.manifest.vcpu,
                memory: self.manifest.memory,
                disk_size: self.manifest.disk_size,
                ports: self
                    .manifest
                    .port_map
                    .iter()
                    .map(|pm| pb::PortMapping {
                        protocol: pm.protocol.as_str().into(),
                        host_port: pm.from as u32,
                        vm_port: pm.to as u32,
                    })
                    .collect(),
            }),
            app_url: self.instance_id.as_ref().map(|id| {
                format!(
                    "https://{id}-{}.{}:{}",
                    gw.tappd_port, gw.base_domain, gw.port
                )
            }),
            app_id: self.manifest.app_id.as_str().into(),
            instance_id: self.instance_id.as_deref().map(Into::into),
        }
    }
}

impl VmConfig {
    pub fn merge_info(&self, proc_state: Option<&ProcessInfo>, workdir: &VmWorkDir) -> VmInfo {
        fn truncate(d: Duration) -> Duration {
            Duration::from_secs(d.as_secs())
        }
        let is_running = match proc_state {
            Some(info) => info.state.status.is_running(),
            None => false,
        };
        let todo = "more light way to get started";
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
            manifest: self.manifest.clone(),
            workdir: workdir.path().to_path_buf(),
            instance_id,
            status,
            uptime,
            exited_at: Some(exited_at),
        }
    }

    pub fn config_qemu(&self, qemu: &Path, workdir: impl AsRef<Path>, cid: u32) -> Result<ProcessConfig> {
        let workdir = VmWorkDir::new(workdir);
        let serial_file = workdir.serial_file();
        let shared_dir = workdir.shared_dir();
        let disk_size = format!("{}G", self.manifest.disk_size);
        let hda_path = workdir.hda_path();
        if !hda_path.exists() {
            create_hd(&hda_path, self.image.hda.as_ref(), &disk_size)?;
        }
        if !shared_dir.exists() {
            fs::create_dir_all(&shared_dir)?;
        }
        let mut command = Command::new(qemu);
        command.arg("-accel").arg("kvm");
        command.arg("-cpu").arg("host");
        command.arg("-smp").arg(self.manifest.vcpu.to_string());
        command.arg("-m").arg(format!("{}M", self.manifest.memory));
        command.arg("-nographic");
        command.arg("-nodefaults");
        command
            .arg("-serial")
            .arg(format!("file:{}", serial_file.display()));
        command.arg("-kernel").arg(&self.image.kernel);
        command.arg("-initrd").arg(&self.image.initrd);
        command
            .arg("-drive")
            .arg(format!("file={},if=none,id=hd0", hda_path.display()))
            .arg("-device")
            .arg(format!("virtio-blk-pci,drive=hd0"));
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
            .arg(format!("vhost-vsock-pci,guest-cid={}", cid));
        command.arg("-virtfs").arg(format!(
            "local,path={},mount_tag=host-shared,readonly=off,security_model=mapped,id=virtfs0",
            shared_dir.display()
        ));
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
        let process_config = ProcessConfig {
            id: self.manifest.id.clone(),
            args,
            name: self.manifest.name.clone(),
            command: qemu.to_string_lossy().to_string(),
            env: Default::default(),
            cwd: workdir.to_string_lossy().to_string(),
            stdout: stdout_path.to_string_lossy().to_string(),
            stderr: stderr_path.to_string_lossy().to_string(),
            pidfile: pidfile_path.to_string_lossy().to_string(),
            cid: self.tdx_config.as_ref().map(|cfg| cfg.cid),
            note: "".into(),
        };
        Ok(process_config)
    }
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
        self.shared_dir().join("app-compose.json")
    }

    pub fn encrypted_env_path(&self) -> PathBuf {
        self.shared_dir().join("encrypted-env")
    }

    pub fn serial_file(&self) -> PathBuf {
        self.workdir.join("serial.log")
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

    pub fn path(&self) -> &Path {
        &self.workdir
    }

    pub fn instance_info_path(&self) -> PathBuf {
        self.shared_dir().join(".instance_info")
    }
}

impl VmWorkDir {
    pub fn instance_info(&self) -> Result<InstanceInfo> {
        let info_file = self.instance_info_path();
        let info: InstanceInfo = serde_json::from_slice(&fs::read(&info_file)?)?;
        Ok(info)
    }
}
