// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::process::{Process, ProcessConfig, ProcessInfo};
use anyhow::{bail, Context, Result};
use dashmap::DashMap;
use std::{
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tracing::info;

#[derive(Clone)]
pub struct Supervisor {
    state: Arc<SupervisorState>,
}

impl Deref for Supervisor {
    type Target = SupervisorState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

pub struct SupervisorState {
    freezed: AtomicBool,
    processes: DashMap<String, Process>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            state: Arc::new(SupervisorState {
                freezed: AtomicBool::new(false),
                processes: DashMap::new(),
            }),
        }
    }

    fn freezed(&self) -> bool {
        self.state.freezed.load(Ordering::Relaxed)
    }

    fn set_freezed(&self, freezed: bool) {
        self.state.freezed.store(freezed, Ordering::Relaxed);
    }

    pub fn deploy(&self, config: ProcessConfig) -> Result<()> {
        if self.freezed() {
            bail!("Supervisor is freezed");
        }
        let id = config.id.clone();
        if id.is_empty() {
            return Err(anyhow::anyhow!("Process ID is empty"));
        }
        if self
            .info(&id)
            .is_some_and(|info| info.state.status.is_running())
        {
            bail!("Process is already running");
        }
        let process = Process::new(config);
        process.start()?;
        info!("Deployed process {id}");
        self.processes.insert(id, process);
        Ok(())
    }

    pub fn start(&self, id: &str) -> Result<()> {
        let process = self.processes.get(id).context("Process not found")?;
        info!("Starting process {id}");
        process.start()
    }

    pub fn stop(&self, id: &str) -> Result<()> {
        let process = self.processes.get(id).context("Process not found")?;
        info!("Stopping process {id}");
        process.stop()
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        let process = self.processes.get(id).context("Process not found")?;
        if process.lock().is_started() {
            bail!("Process is started");
        }
        if process.lock().is_running() {
            bail!("Process is running");
        }
        drop(process);
        self.processes.remove(id);
        info!("Removed process {id}");
        Ok(())
    }

    pub fn list(&self) -> Vec<ProcessInfo> {
        self.processes
            .iter()
            .map(|pair| pair.value().info())
            .collect::<Vec<_>>()
    }

    pub fn info(&self, id: &str) -> Option<ProcessInfo> {
        self.processes.get(id).map(|process| process.info())
    }

    /// Forget every process that has finished.
    ///
    /// A running one is kept, for the reason [`Self::remove`] keeps it: the
    /// handle is the only way to stop it. Dropping it does not leave the child
    /// running -- the kill channel goes with the handle, which makes the wait
    /// task SIGKILL the child -- so clearing the map used to take down every
    /// supervised process at once, with no stop, no grace and no record of it
    /// anywhere. Use `/stop` or `/shutdown` to stop a process; `/clear` only
    /// drops what has already stopped.
    pub fn clear(&self) -> Result<()> {
        let mut running = vec![];
        self.processes.retain(|id, process| {
            let state = process.lock();
            let keep = state.is_started() || state.is_running();
            if keep {
                running.push(id.clone());
            }
            keep
        });
        if !running.is_empty() {
            bail!("processes are still running: {}", running.join(", "));
        }
        info!("Cleared stopped processes");
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.set_freezed(true);
        // Fixme: race condition here, there might be on going deployments
        let mut n_running = 0;
        for i in 0..10 {
            n_running = 0;
            for pair in self.processes.iter() {
                let process = pair.value();
                let is_running = process.lock().is_running();
                if is_running {
                    process.stop().ok();
                    n_running += 1;
                }
            }
            if n_running == 0 {
                return Ok(());
            }
            info!("Waiting {n_running} processes to stop");
            tokio::time::sleep(Duration::from_millis(50 + 200 * i)).await;
        }
        bail!("Failed to stop {n_running} processes");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sleeper(id: &str) -> ProcessConfig {
        ProcessConfig {
            id: id.to_string(),
            name: id.to_string(),
            command: "sleep".to_string(),
            args: vec!["60".to_string()],
            env: HashMap::new(),
            cwd: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            pidfile: String::new(),
            cid: None,
            note: String::new(),
        }
    }

    /// Whether `pid` is a live process rather than a reaped or reaping one.
    fn running(pid: u32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let Some((_, after_name)) = stat.rsplit_once(") ") else {
            return false;
        };
        !after_name.starts_with('Z')
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn clear_does_not_leave_a_running_child_behind() {
        let supervisor = Supervisor::new();
        supervisor.deploy(sleeper("one")).unwrap();
        let pid = supervisor.info("one").unwrap().state.pid.unwrap();
        assert!(running(pid), "the child did not start");

        let _ = supervisor.clear();
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(
            !running(pid) || supervisor.info("one").is_some(),
            "clear() left pid {pid} running with no handle to stop it"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn clear_keeps_a_running_process_and_says_so() {
        let supervisor = Supervisor::new();
        supervisor.deploy(sleeper("one")).unwrap();
        let pid = supervisor.info("one").unwrap().state.pid.unwrap();

        let err = supervisor
            .clear()
            .expect_err("a running process was dropped");
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(err.to_string().contains("one"), "{err}");
        assert!(supervisor.info("one").is_some(), "the handle was dropped");
        assert!(
            running(pid),
            "the child was killed by a request to forget it"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn clear_drops_a_process_that_has_finished() {
        let supervisor = Supervisor::new();
        let mut config = sleeper("one");
        config.args = vec!["0".to_string()];
        supervisor.deploy(config).unwrap();
        for _ in 0..50 {
            if !supervisor.info("one").unwrap().state.status.is_running() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        supervisor.stop("one").unwrap();

        supervisor.clear().unwrap();

        assert!(supervisor.info("one").is_none());
    }
}
