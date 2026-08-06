// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use supervisor_client::supervisor::{ProcessConfig, ProcessInfo, ProcessState, ProcessStatus};
use supervisor_client::SupervisorClient;
use tokio::process::Command;

#[derive(Clone)]
pub enum ProcessManager {
    Supervisor(SupervisorClient),
    Systemd(Arc<SystemdProcessManager>),
}

impl ProcessManager {
    pub fn supervisor(client: SupervisorClient) -> Self {
        Self::Supervisor(client)
    }

    pub fn systemd(state_dir: PathBuf, unit_prefix: String) -> Result<Self> {
        Ok(Self::Systemd(Arc::new(SystemdProcessManager::new(
            state_dir,
            unit_prefix,
        )?)))
    }

    pub async fn deploy(&self, config: &ProcessConfig) -> Result<()> {
        match self {
            Self::Supervisor(client) => client.deploy(config).await,
            Self::Systemd(manager) => manager.deploy(config).await,
        }
    }

    pub async fn stop(&self, id: &str) -> Result<()> {
        match self {
            Self::Supervisor(client) => client.stop(id).await,
            Self::Systemd(manager) => manager.stop(id).await,
        }
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        match self {
            Self::Supervisor(client) => client.remove(id).await,
            Self::Systemd(manager) => manager.remove(id).await,
        }
    }

    pub async fn list(&self) -> Result<Vec<ProcessInfo>> {
        match self {
            Self::Supervisor(client) => client.list().await,
            Self::Systemd(manager) => manager.list().await,
        }
    }

    pub async fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        match self {
            Self::Supervisor(client) => client.info(id).await,
            Self::Systemd(manager) => manager.info(id).await,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessRecord {
    config: ProcessConfig,
    started: bool,
}

pub struct SystemdProcessManager {
    state_dir: PathBuf,
    unit_prefix: String,
}

impl SystemdProcessManager {
    fn new(state_dir: PathBuf, unit_prefix: String) -> Result<Self> {
        anyhow::ensure!(
            !unit_prefix.is_empty(),
            "systemd unit prefix must not be empty"
        );
        anyhow::ensure!(
            unit_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "systemd unit prefix contains unsupported characters"
        );
        fs_err::create_dir_all(&state_dir).context("failed to create systemd process state dir")?;
        Ok(Self {
            state_dir,
            unit_prefix,
        })
    }

    fn key(id: &str) -> String {
        hex::encode(Sha256::digest(id.as_bytes()))
    }

    fn unit(&self, id: &str) -> String {
        format!("{}-{}.service", self.unit_prefix, Self::key(id))
    }

    fn record_path(&self, id: &str) -> PathBuf {
        self.state_dir.join(format!("{}.json", Self::key(id)))
    }

    fn read_record(&self, id: &str) -> Result<ProcessRecord> {
        let path = self.record_path(id);
        let raw =
            fs_err::read(&path).with_context(|| format!("process record not found for {id}"))?;
        serde_json::from_slice(&raw).context("failed to parse systemd process record")
    }

    fn write_record(&self, record: &ProcessRecord) -> Result<()> {
        let path = self.record_path(&record.config.id);
        safe_write::safe_write(path, serde_json::to_vec_pretty(record)?)
            .context("failed to persist systemd process record")
    }

    async fn command(mut command: Command, operation: &str) -> Result<std::process::Output> {
        let output = command
            .output()
            .await
            .with_context(|| format!("failed to execute {operation}"))?;
        if !output.status.success() {
            bail!(
                "{operation} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output)
    }

    async fn launch(&self, config: &ProcessConfig) -> Result<()> {
        let unit = self.unit(&config.id);
        let mut command = Command::new("systemd-run");
        command
            .arg("--quiet")
            .arg("--unit")
            .arg(&unit)
            .arg("--service-type=exec")
            .arg("--property=KillMode=mixed")
            .arg("--property=KillSignal=SIGTERM")
            .arg("--property=SendSIGKILL=yes")
            .arg("--property=TimeoutStopSec=infinity")
            .arg("--property=ExitType=cgroup")
            .arg("--property=Restart=no")
            .arg(format!("--description=dstack VM process {}", config.id));

        if !config.cwd.is_empty() {
            command.arg(format!("--working-directory={}", config.cwd));
        }
        if config.stdout.is_empty() {
            command.arg("--property=StandardOutput=null");
        } else {
            command.arg(format!(
                "--property=StandardOutput=append:{}",
                config.stdout
            ));
        }
        if config.stderr.is_empty() {
            command.arg("--property=StandardError=null");
        } else {
            command.arg(format!("--property=StandardError=append:{}", config.stderr));
        }
        for (key, value) in &config.env {
            command.arg(format!("--setenv={key}={value}"));
        }
        command.arg("--").arg(&config.command).args(&config.args);
        Self::command(command, "systemd-run").await?;

        if !config.pidfile.is_empty() {
            if let Some(info) = self.info(&config.id).await? {
                if let Some(pid) = info.state.pid {
                    fs_err::write(&config.pidfile, pid.to_string())
                        .context("failed to write systemd process pidfile")?;
                }
            }
        }
        Ok(())
    }

    async fn deploy(&self, config: &ProcessConfig) -> Result<()> {
        if self
            .info(&config.id)
            .await?
            .is_some_and(|info| info.state.status.is_running())
        {
            bail!("Process is already running");
        }
        let record = ProcessRecord {
            config: config.clone(),
            started: true,
        };
        self.write_record(&record)?;
        if let Err(error) = self.launch(config).await {
            let _ = fs_err::remove_file(self.record_path(&config.id));
            return Err(error);
        }
        Ok(())
    }

    async fn stop(&self, id: &str) -> Result<()> {
        let mut record = self.read_record(id)?;
        record.started = false;
        self.write_record(&record)?;

        if self
            .info(id)
            .await?
            .is_some_and(|info| info.state.status.is_running())
        {
            let mut command = Command::new("systemctl");
            command.arg("stop").arg("--no-block").arg(self.unit(id));
            Self::command(command, "systemctl stop").await?;
        }
        Ok(())
    }

    async fn remove(&self, id: &str) -> Result<()> {
        if self
            .info(id)
            .await?
            .is_some_and(|info| info.state.status.is_running())
        {
            bail!("Process is running");
        }
        let record = self.read_record(id)?;
        if record.started {
            bail!("Process is started");
        }
        let mut command = Command::new("systemctl");
        command.arg("reset-failed").arg(self.unit(id));
        let _ = command.output().await;
        fs_err::remove_file(self.record_path(id)).context("failed to remove process record")
    }

    async fn list(&self) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        for entry in fs_err::read_dir(&self.state_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let raw = fs_err::read(entry.path())?;
            let record: ProcessRecord = serde_json::from_slice(&raw)?;
            if let Some(info) = self.info_from_record(record).await? {
                processes.push(info);
            }
        }
        Ok(processes)
    }

    async fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        let path = self.record_path(id);
        if !path.exists() {
            return Ok(None);
        }
        self.info_from_record(self.read_record(id)?).await
    }

    async fn info_from_record(&self, record: ProcessRecord) -> Result<Option<ProcessInfo>> {
        let unit = self.unit(&record.config.id);
        let mut command = Command::new("systemctl");
        command
            .arg("show")
            .arg(&unit)
            .arg("--property=LoadState,ActiveState,SubState,MainPID,ExecMainCode,ExecMainStatus")
            .stdout(Stdio::piped());
        let output = command
            .output()
            .await
            .context("failed to execute systemctl show")?;
        let properties = String::from_utf8_lossy(&output.stdout);
        let value = |name: &str| {
            properties
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .unwrap_or_default()
        };
        let load_state = value("LoadState");
        let active_state = value("ActiveState");
        let sub_state = value("SubState");
        let running = matches!(active_state, "active" | "activating" | "deactivating")
            || matches!(
                sub_state,
                "running" | "start" | "stop-sigterm" | "stop-sigkill"
            );
        let status = if running {
            ProcessStatus::Running
        } else if !record.started {
            ProcessStatus::Stopped
        } else if load_state == "not-found" || active_state == "inactive" {
            ProcessStatus::Exited(value("ExecMainStatus").parse().unwrap_or_default())
        } else {
            ProcessStatus::Error(format!(
                "systemd unit is {active_state}/{sub_state} (code={}, status={})",
                value("ExecMainCode"),
                value("ExecMainStatus")
            ))
        };
        let pid = value("MainPID").parse().ok().filter(|pid| *pid != 0);
        Ok(Some(ProcessInfo {
            config: record.config,
            state: ProcessState {
                status,
                started: record.started,
                pid,
                started_at: None,
                stopped_at: None,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_names_are_stable_and_do_not_embed_process_ids() {
        let manager =
            SystemdProcessManager::new(PathBuf::from("/tmp/test"), "dstack-vm".into()).unwrap();
        assert_eq!(manager.unit("vm/one"), manager.unit("vm/one"));
        assert_ne!(manager.unit("vm/one"), manager.unit("vm-two"));
        assert!(!manager.unit("vm/one").contains("vm/one"));
    }
}
