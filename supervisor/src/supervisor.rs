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

    pub fn clear(&self) {
        self.processes.clear();
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
