// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use supervisor_client::supervisor::{ProcessConfig, ProcessInfo, ProcessState, ProcessStatus};
use supervisor_client::SupervisorClient;
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::{validate_open_file, validate_unit_user};

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

    pub fn systemd_backend(
        state_dir: PathBuf,
        unit_prefix: String,
        stop_timeout: String,
    ) -> Result<Arc<SystemdProcessManager>> {
        Ok(Arc::new(SystemdProcessManager::new(
            state_dir,
            unit_prefix,
            stop_timeout,
        )?))
    }

    pub fn systemd(backend: Arc<SystemdProcessManager>) -> Self {
        Self::Systemd(backend)
    }

    pub async fn auto(
        systemd: Arc<SystemdProcessManager>,
        supervisor: Option<SupervisorClient>,
    ) -> Result<Self> {
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
            Self::Supervisor(client) => {
                ensure_supervisor_supported(config)?;
                client.deploy(config).await
            }
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

/// Rejects a process asking for something Supervisor cannot provide.
///
/// Supervisor spawns processes with its own privileges and without pre-opened
/// file descriptors. Launching anyway would run a VM as root that asked to be
/// confined, or leave QEMU pointing at whatever the fd number happens to be,
/// so this fails before anything is spawned.
fn ensure_supervisor_supported(config: &ProcessConfig) -> Result<()> {
    for (what, unsupported) in [
        ("pre-opened files", !config.open_files.is_empty()),
        ("a dedicated user", !config.user.is_empty()),
    ] {
        if unsupported {
            bail!(
                "process {} requires {what}, which only the systemd process manager supports; set cvm.pm = \"systemd\" or \"auto\"",
                config.id
            );
        }
    }
    Ok(())
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
        // Concurrent deploys of the same ID are not serialized here; one wins
        // the handoff and the other fails on record/unit removal or collision.
        if self.is_supervisor_process(&config.id).await {
            let supervisor = self.supervisor()?;
            match supervisor.info(&config.id).await? {
                Some(info) if info.state.status.is_running() => {
                    bail!("process is already running")
                }
                Some(_) => {
                    // Natural exits leave Supervisor's `started` flag set.
                    // Normalize it before removing the legacy record.
                    supervisor.stop(&config.id).await?;
                    supervisor.remove(&config.id).await?;
                }
                None => {
                    // Supervisor may have restarted or the record may have
                    // been removed out of band. It is already safe to migrate.
                }
            }
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
                    let present = legacy
                        .iter()
                        .map(|process| process.config.id.as_str())
                        .collect::<std::collections::HashSet<_>>();
                    cache.retain(|id, _| present.contains(id.as_str()));
                    for process in &legacy {
                        if let Some(cached) = cache.get_mut(&process.config.id) {
                            *cached = process.clone();
                        }
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
                        if let Some(cached) = self.supervisor_processes.write().await.get_mut(id) {
                            *cached = process.clone();
                        }
                    } else {
                        self.supervisor_processes.write().await.remove(id);
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

fn system_time_from_monotonic_micros(value: &str) -> Option<SystemTime> {
    let target = value.parse::<u64>().ok().filter(|value| *value != 0)?;
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` points to a valid timespec. systemd's monotonic timestamp
    // properties use CLOCK_MONOTONIC through its dual_timestamp helpers.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return None;
    }
    let now_micros = (now.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add((now.tv_nsec as u64) / 1_000);
    SystemTime::now().checked_sub(Duration::from_micros(now_micros.saturating_sub(target)))
}

fn state_from_systemd_properties(
    properties: &str,
    started: bool,
) -> (
    ProcessStatus,
    Option<u32>,
    Option<SystemTime>,
    Option<SystemTime>,
) {
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
    let plain_status = value("ExecMainStatus").parse::<i32>().unwrap_or_default();
    let raw_status = match value("ExecMainCode") {
        "exited" => plain_status << 8,
        "dumped" => plain_status | 0x80,
        _ => plain_status,
    };
    let status = if running {
        ProcessStatus::Running
    } else if !started && raw_status == 0 {
        ProcessStatus::Stopped
    } else if load_state == "not-found" || matches!(active_state, "inactive" | "failed") {
        // A collected unit has no status properties, so a started record can
        // only be represented as a clean exit after daemon reload/reboot.
        ProcessStatus::Exited(raw_status)
    } else {
        ProcessStatus::Error(format!(
            "systemd unit is {active_state}/{sub_state} (code={}, status={})",
            value("ExecMainCode"),
            value("ExecMainStatus")
        ))
    };
    let pid = value("MainPID").parse().ok().filter(|pid| *pid != 0);
    let started_at = system_time_from_monotonic_micros(value("ExecMainStartTimestampMonotonic"));
    let stopped_at = system_time_from_monotonic_micros(value("InactiveEnterTimestampMonotonic"));
    (status, pid, started_at, stopped_at)
}

pub struct SystemdProcessManager {
    state_dir: PathBuf,
    unit_prefix: String,
    stop_timeout: String,
}

impl SystemdProcessManager {
    fn new(state_dir: PathBuf, unit_prefix: String, stop_timeout: String) -> Result<Self> {
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
            stop_timeout,
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

    fn run_args(&self, config: &ProcessConfig, unit: &str) -> Result<Vec<String>> {
        let mut args = vec![
            "--quiet".into(),
            "--unit".into(),
            unit.to_string(),
            "--service-type=exec".into(),
            "--property=KillMode=mixed".into(),
            "--property=KillSignal=SIGTERM".into(),
            "--property=SendSIGKILL=yes".into(),
            format!("--property=TimeoutStopSec={}", self.stop_timeout),
            "--property=ExitType=cgroup".into(),
            "--property=Restart=no".into(),
            format!("--description=dstack VM process {}", config.id),
        ];

        if !config.cwd.is_empty() {
            args.push(format!("--working-directory={}", config.cwd));
        }
        if config.stdout.is_empty() {
            args.push("--property=StandardOutput=null".into());
        } else {
            args.push(format!(
                "--property=StandardOutput=append:{}",
                config.stdout
            ));
        }
        if config.stderr.is_empty() {
            args.push("--property=StandardError=null".into());
        } else {
            args.push(format!("--property=StandardError=append:{}", config.stderr));
        }
        for (key, value) in &config.env {
            args.push(format!("--setenv={key}={value}"));
        }
        if !config.user.is_empty() {
            validate_unit_user("user", &config.user)?;
            args.push(format!("--property=User={}", config.user));
        }
        // systemd opens these before exec and passes them in declaration
        // order starting at fd 3, which is what the QEMU netdev arguments
        // reference. No fdname and no `graceful` option: a missing device must
        // fail the unit instead of shifting every later descriptor by one.
        //
        // systemd.exec(5): "The file or socket is opened by the service
        // manager and the file descriptor is passed to the service." The open
        // therefore happens with the manager's privileges, before the `User=`
        // drop that lands just before exec, so a root-owned chardev such as
        // /dev/tapN does not have to be chowned to the QEMU user.
        for path in &config.open_files {
            validate_open_file("open_files entry", path)?;
            args.push(format!("--property=OpenFile={path}"));
        }
        args.push("--".into());
        args.push(config.command.clone());
        args.extend(config.args.iter().cloned());
        Ok(args)
    }

    async fn launch(&self, config: &ProcessConfig) -> Result<()> {
        let unit = self.unit(&config.id);
        // Failed transient units remain loaded until reset and otherwise
        // prevent automatic restart from reusing the unit name.
        let mut reset = Command::new("systemctl");
        reset.arg("reset-failed").arg(&unit);
        let _ = reset.output().await;
        let mut command = Command::new("systemd-run");
        command.args(self.run_args(config, &unit)?);
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
            if let Err(error) = Self::command(command, "systemctl stop").await {
                // The unit may have exited and been collected between the
                // preceding status query and this stop request.
                if self
                    .info(id)
                    .await?
                    .is_some_and(|info| info.state.status.is_running())
                {
                    return Err(error);
                }
            }
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
            // A per-record parse error is isolated above. A systemd-wide
            // query error is propagated so callers cannot lose CID ownership
            // and mistake a running VM for a stopped one.
            processes.push(self.info_from_record(record).await?);
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
            .arg(
                "--property=LoadState,ActiveState,SubState,MainPID,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,InactiveEnterTimestampMonotonic",
            );
        // A bus failure must not be mapped to a stopped VM: callers rely on an
        // error here to avoid rotating logs and attempting duplicate restarts.
        let output = Self::command(command, "systemctl show").await?;
        let properties = String::from_utf8_lossy(&output.stdout);
        let (status, pid, started_at, stopped_at) =
            state_from_systemd_properties(&properties, record.started);
        Ok(ProcessInfo {
            config: record.config,
            state: ProcessState {
                status,
                started: record.started,
                pid,
                started_at,
                stopped_at,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_names_are_stable_and_do_not_embed_process_ids() {
        let (_dir, manager) = test_manager();
        assert_eq!(manager.unit("vm/one"), manager.unit("vm/one"));
        assert_ne!(manager.unit("vm/one"), manager.unit("vm-two"));
        assert!(!manager.unit("vm/one").contains("vm/one"));
    }

    fn test_config(open_files: &[&str]) -> ProcessConfig {
        test_config_as("", open_files)
    }

    fn test_config_as(user: &str, open_files: &[&str]) -> ProcessConfig {
        ProcessConfig {
            id: "vm/one".into(),
            name: "vm".into(),
            command: "/usr/bin/qemu".into(),
            args: vec!["-netdev".into(), "tap,id=net0,fd=3".into()],
            env: HashMap::new(),
            cwd: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            pidfile: String::new(),
            cid: None,
            note: String::new(),
            user: user.into(),
            open_files: open_files.iter().map(|path| path.to_string()).collect(),
        }
    }

    fn test_manager() -> (tempfile::TempDir, SystemdProcessManager) {
        let dir = tempfile::tempdir().unwrap();
        let manager = SystemdProcessManager::new(
            dir.path().to_path_buf(),
            "dstack-vm".into(),
            "infinity".into(),
        )
        .unwrap();
        (dir, manager)
    }

    #[test]
    fn renders_open_files_as_ordered_unit_properties() {
        let (_dir, manager) = test_manager();
        let args = manager
            .run_args(
                &test_config(&["/dev/tap7498", "/dev/tap7499"]),
                "unit.service",
            )
            .unwrap();
        let properties = args
            .iter()
            .take_while(|arg| *arg != "--")
            .filter_map(|arg| arg.strip_prefix("--property=OpenFile="))
            .collect::<Vec<_>>();
        assert_eq!(properties, ["/dev/tap7498", "/dev/tap7499"]);
        assert_eq!(args.last().unwrap(), "tap,id=net0,fd=3");

        assert!(!manager
            .run_args(&test_config(&[]), "unit.service")
            .unwrap()
            .iter()
            .any(|arg| arg.contains("OpenFile")));
    }

    #[test]
    fn rejects_open_files_that_would_change_the_unit_property() {
        let (_dir, manager) = test_manager();
        for path in ["relative/tap", "/dev/tap:0", "/dev/%i/tap"] {
            manager
                .run_args(&test_config(&[path]), "unit.service")
                .unwrap_err();
        }
    }

    #[test]
    fn renders_the_privilege_drop_as_a_unit_property() {
        let (_dir, manager) = test_manager();
        let args = manager
            .run_args(&test_config_as("qemu", &["/dev/tap7498"]), "unit.service")
            .unwrap();
        assert!(args.iter().any(|arg| arg == "--property=User=qemu"));
        // The privilege drop replaces the sudo prefix rather than joining it.
        assert!(!args.iter().any(|arg| arg == "sudo"));

        assert!(!manager
            .run_args(&test_config(&[]), "unit.service")
            .unwrap()
            .iter()
            .any(|arg| arg.contains("User=")));

        for user in ["qemu:0", "qemu user", "%i", "-qemu"] {
            manager
                .run_args(&test_config_as(user, &[]), "unit.service")
                .unwrap_err();
        }
    }

    #[test]
    fn supervisor_backend_rejects_what_it_cannot_provide() {
        ensure_supervisor_supported(&test_config(&[])).unwrap();
        for config in [test_config(&["/dev/tap7498"]), test_config_as("qemu", &[])] {
            let error = ensure_supervisor_supported(&config).unwrap_err();
            assert!(error.to_string().contains("systemd"), "{error:#}");
        }
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
                "LoadState=loaded\nActiveState=failed\nExecMainCode=exited\nExecMainStatus=3",
                false
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
