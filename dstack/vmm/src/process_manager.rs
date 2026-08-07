// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use supervisor_client::supervisor::{ProcessConfig, ProcessInfo, ProcessState, ProcessStatus};
use supervisor_client::SupervisorClient;
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::warn;

#[derive(Clone)]
pub enum ProcessManager {
    Supervisor(SupervisorClient),
    Systemd(Arc<SystemdProcessManager>),
    Auto(Arc<AutoProcessManager>),
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

    pub async fn auto(systemd: Self, supervisor: Option<SupervisorClient>) -> Result<Self> {
        let Self::Systemd(systemd) = systemd else {
            bail!("auto process manager requires a systemd backend");
        };
        let mut supervisor_processes = HashMap::new();
        if let Some(client) = &supervisor {
            for process in client.list().await? {
                supervisor_processes.insert(process.config.id.clone(), process);
            }
        }
        Ok(Self::Auto(Arc::new(AutoProcessManager {
            systemd,
            supervisor,
            supervisor_processes: RwLock::new(supervisor_processes),
        })))
    }

    pub async fn deploy(&self, config: &ProcessConfig) -> Result<()> {
        match self {
            Self::Supervisor(client) => client.deploy(config).await,
            Self::Systemd(manager) => manager.deploy(config).await,
            Self::Auto(manager) => manager.deploy(config).await,
        }
    }

    pub async fn stop(&self, id: &str) -> Result<()> {
        match self {
            Self::Supervisor(client) => client.stop(id).await,
            Self::Systemd(manager) => manager.stop(id).await,
            Self::Auto(manager) => manager.stop(id).await,
        }
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        match self {
            Self::Supervisor(client) => client.remove(id).await,
            Self::Systemd(manager) => manager.remove(id).await,
            Self::Auto(manager) => manager.remove(id).await,
        }
    }

    pub async fn list(&self) -> Result<Vec<ProcessInfo>> {
        match self {
            Self::Supervisor(client) => client.list().await,
            Self::Systemd(manager) => manager.list().await,
            Self::Auto(manager) => manager.list().await,
        }
    }

    pub async fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        match self {
            Self::Supervisor(client) => client.info(id).await,
            Self::Systemd(manager) => manager.info(id).await,
            Self::Auto(manager) => manager.info(id).await,
        }
    }
}

pub struct AutoProcessManager {
    systemd: Arc<SystemdProcessManager>,
    supervisor: Option<SupervisorClient>,
    /// VM processes found running in Supervisor when the VMM started. They
    /// stay pinned to Supervisor until their next deploy.
    supervisor_processes: RwLock<HashMap<String, ProcessInfo>>,
}

impl AutoProcessManager {
    async fn is_supervisor_process(&self, id: &str) -> bool {
        self.supervisor_processes.read().await.contains_key(id)
    }

    fn supervisor(&self) -> Result<&SupervisorClient> {
        self.supervisor
            .as_ref()
            .context("legacy supervisor is unavailable")
    }

    async fn deploy(&self, config: &ProcessConfig) -> Result<()> {
        // VMM start operations are serialized by the caller. If that changes,
        // migration should gain a per-ID lock spanning this handoff.
        if self.is_supervisor_process(&config.id).await {
            let supervisor = self.supervisor()?;
            if supervisor
                .info(&config.id)
                .await?
                .is_some_and(|info| info.state.status.is_running())
            {
                bail!("process is already running");
            }
            // Natural exits leave Supervisor's `started` flag set. Normalize
            // it before removing the legacy record and migrating this launch.
            supervisor.stop(&config.id).await?;
            supervisor.remove(&config.id).await?;
            self.supervisor_processes.write().await.remove(&config.id);
        }
        self.systemd.deploy(config).await
    }

    async fn stop(&self, id: &str) -> Result<()> {
        if self.is_supervisor_process(id).await {
            self.supervisor()?.stop(id).await
        } else {
            self.systemd.stop(id).await
        }
    }

    async fn remove(&self, id: &str) -> Result<()> {
        if self.is_supervisor_process(id).await {
            self.supervisor()?.remove(id).await?;
            self.supervisor_processes.write().await.remove(id);
            Ok(())
        } else {
            self.systemd.remove(id).await
        }
    }

    async fn list(&self) -> Result<Vec<ProcessInfo>> {
        let mut processes = self.systemd.list().await?;
        let pinned = self.supervisor_processes.read().await.clone();
        if !pinned.is_empty() {
            let supervisor = self.supervisor()?;
            match supervisor.list().await {
                Ok(legacy) => {
                    let legacy = legacy
                        .into_iter()
                        .filter(|process| pinned.contains_key(&process.config.id))
                        .collect::<Vec<_>>();
                    let mut cache = self.supervisor_processes.write().await;
                    for process in &legacy {
                        cache.insert(process.config.id.clone(), process.clone());
                    }
                    drop(cache);
                    processes.extend(legacy);
                }
                Err(error) => {
                    warn!(%error, "legacy supervisor is unavailable; using cached pinned VM state");
                    processes.extend(pinned.into_values());
                }
            }
        }
        Ok(processes)
    }

    async fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        if self.is_supervisor_process(id).await {
            match self.supervisor()?.info(id).await {
                Ok(info) => {
                    if let Some(process) = &info {
                        self.supervisor_processes
                            .write()
                            .await
                            .insert(id.to_string(), process.clone());
                    }
                    Ok(info)
                }
                Err(error) => {
                    warn!(%id, %error, "legacy supervisor is unavailable; using cached pinned VM state");
                    Ok(self.supervisor_processes.read().await.get(id).cloned())
                }
            }
        } else {
            self.systemd.info(id).await
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessRecord {
    config: ProcessConfig,
    started: bool,
}

fn state_from_systemd_properties(properties: &str, started: bool) -> (ProcessStatus, Option<u32>) {
    let value = |name: &str| {
        properties
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_default()
    };
    let load_state = value("LoadState");
    let active_state = value("ActiveState");
    let sub_state = value("SubState");
    let running = matches!(active_state, "active" | "activating" | "deactivating");
    let status = if running {
        ProcessStatus::Running
    } else if !started {
        ProcessStatus::Stopped
    } else if load_state == "not-found" || matches!(active_state, "inactive" | "failed") {
        let status = value("ExecMainStatus").parse::<i32>().unwrap_or_default();
        ProcessStatus::Exited(if value("ExecMainCode") == "exited" {
            status << 8
        } else {
            status
        })
    } else {
        ProcessStatus::Error(format!(
            "systemd unit is {active_state}/{sub_state} (code={}, status={})",
            value("ExecMainCode"),
            value("ExecMainStatus")
        ))
    };
    let pid = value("MainPID").parse().ok().filter(|pid| *pid != 0);
    (status, pid)
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
        // Failed transient units remain loaded until reset and otherwise
        // prevent automatic restart from reusing the unit name.
        let mut reset = Command::new("systemctl");
        reset.arg("reset-failed").arg(&unit);
        let _ = reset.output().await;
        let mut command = Command::new("systemd-run");
        command
            .arg("--quiet")
            .arg("--unit")
            .arg(&unit)
            .arg("--service-type=exec")
            .arg("--property=KillMode=mixed")
            .arg("--property=KillSignal=SIGTERM")
            .arg("--property=SendSIGKILL=yes")
            .arg("--property=TimeoutStopSec=30min")
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
            bail!("process is already running");
        }
        let record = ProcessRecord {
            config: config.clone(),
            started: true,
        };
        self.write_record(&record)?;
        self.launch(config).await
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
            bail!("process is running");
        }
        let record = self.read_record(id)?;
        if record.started {
            bail!("process is started");
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
            let path = entry.path();
            let record = fs_err::read(&path)
                .context("failed to read process record")
                .and_then(|raw| serde_json::from_slice::<ProcessRecord>(&raw).map_err(Into::into));
            let record = match record {
                Ok(record) => record,
                Err(error) => {
                    warn!(path = %path.display(), %error, "skipping invalid process record");
                    continue;
                }
            };
            match self.info_from_record(record).await {
                Ok(info) => processes.push(info),
                Err(error) => {
                    warn!(path = %path.display(), %error, "skipping unavailable systemd process")
                }
            }
        }
        Ok(processes)
    }

    async fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        match self.read_record(id) {
            Ok(record) => self.info_from_record(record).await.map(Some),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn info_from_record(&self, record: ProcessRecord) -> Result<ProcessInfo> {
        let unit = self.unit(&record.config.id);
        let mut command = Command::new("systemctl");
        command
            .arg("show")
            .arg(&unit)
            .arg("--property=LoadState,ActiveState,SubState,MainPID,ExecMainCode,ExecMainStatus");
        // `systemctl show` returns non-zero for a collected transient unit but
        // still emits LoadState=not-found, which is a valid stopped state.
        let output = command
            .output()
            .await
            .context("failed to execute systemctl show")?;
        let properties = String::from_utf8_lossy(&output.stdout);
        let (status, pid) = state_from_systemd_properties(&properties, record.started);
        Ok(ProcessInfo {
            config: record.config,
            state: ProcessState {
                status,
                started: record.started,
                pid,
                started_at: None,
                stopped_at: None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_names_are_stable_and_do_not_embed_process_ids() {
        let dir = tempfile::tempdir().unwrap();
        let manager =
            SystemdProcessManager::new(dir.path().to_path_buf(), "dstack-vm".into()).unwrap();
        assert_eq!(manager.unit("vm/one"), manager.unit("vm/one"));
        assert_ne!(manager.unit("vm/one"), manager.unit("vm-two"));
        assert!(!manager.unit("vm/one").contains("vm/one"));
    }

    #[test]
    fn maps_systemd_states_to_process_status() {
        let state = |properties, started| state_from_systemd_properties(properties, started).0;
        assert!(matches!(
            state("ActiveState=active\nSubState=running\nMainPID=42", true),
            ProcessStatus::Running
        ));
        assert!(matches!(
            state("ActiveState=deactivating\nSubState=stop-sigterm", false),
            ProcessStatus::Running
        ));
        assert!(matches!(
            state("LoadState=not-found\nActiveState=inactive", false),
            ProcessStatus::Stopped
        ));
        assert!(matches!(
            state(
                "LoadState=loaded\nActiveState=failed\nExecMainCode=exited\nExecMainStatus=3",
                true
            ),
            ProcessStatus::Exited(768)
        ));
        assert!(matches!(
            state(
                "LoadState=loaded\nActiveState=failed\nExecMainCode=killed\nExecMainStatus=9",
                true
            ),
            ProcessStatus::Exited(9)
        ));
    }
}
