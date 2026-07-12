// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use bon::Builder;
use fs_err as fs;
use notify::{RecursiveMode, Watcher};
use or_panic::ResultOrPanic;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::marker::Unpin;
use std::path::Path;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::Instrument;
use tracing::{error, info};

#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub pidfile: String,
    #[serde(default)]
    pub cid: Option<u32>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub config: ProcessConfig,
    pub state: ProcessState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessState {
    pub status: ProcessStatus,
    pub started: bool,
    pub pid: Option<u32>,
    #[serde(with = "systime")]
    pub started_at: Option<SystemTime>,
    #[serde(with = "systime")]
    pub stopped_at: Option<SystemTime>,
}

#[derive(Debug)]
pub(crate) struct ProcessStateRT {
    status: ProcessStatus,
    started: bool,
    pid: Option<u32>,
    kill_tx: Option<oneshot::Sender<()>>,
    started_at: Option<SystemTime>,
    stopped_at: Option<SystemTime>,
}

impl ProcessStateRT {
    pub(crate) fn is_running(&self) -> bool {
        self.status.is_running()
    }

    pub(crate) fn is_started(&self) -> bool {
        self.started
    }
}

impl ProcessStateRT {
    pub fn display(&self) -> ProcessState {
        ProcessState {
            status: self.status.clone(),
            started: self.started,
            pid: self.pid,
            started_at: self.started_at,
            stopped_at: self.stopped_at,
        }
    }
}

mod systime {
    use or_panic::ResultOrPanic;
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub(crate) fn serialize<S: Serializer>(
        time: &Option<SystemTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        time.map(|t| {
            t.duration_since(UNIX_EPOCH)
                .or_panic("since zero should never fail")
                .as_secs()
        })
        .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SystemTime>, D::Error> {
        let Some(secs) = Option::<u64>::deserialize(deserializer)? else {
            return Ok(None);
        };
        let time = UNIX_EPOCH
            .checked_add(Duration::from_secs(secs))
            .ok_or_else(|| D::Error::custom("invalid unix timestamp"))?;
        Ok(Some(time))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    Running,
    Stopped,
    Exited(i32),
    Error(String),
}

impl ProcessStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, ProcessStatus::Running)
    }

    pub fn is_stopped(&self) -> bool {
        matches!(self, ProcessStatus::Stopped)
    }
}

#[derive(Clone)]
pub(crate) struct Process {
    config: Arc<ProcessConfig>,
    state: Arc<Mutex<ProcessStateRT>>,
}

impl Process {
    pub fn new(config: ProcessConfig) -> Self {
        Self {
            config: Arc::new(config),
            state: Arc::new(Mutex::new(ProcessStateRT {
                pid: None,
                kill_tx: None,
                status: ProcessStatus::Stopped,
                started: false,
                started_at: None,
                stopped_at: None,
            })),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, ProcessStateRT> {
        self.state.lock().or_panic("lock should never fail")
    }

    pub fn start(&self) -> Result<()> {
        if self.lock().is_running() {
            bail!("Process is already running");
        }

        // Create command and spawn process
        let mut command = Command::new(&self.config.command);
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(&self.config.args)
            .envs(&self.config.env)
            .kill_on_drop(true);
        if !self.config.cwd.is_empty() {
            command.current_dir(&self.config.cwd);
        }
        if !self.config.stdout.is_empty() {
            command.stdout(Stdio::piped());
        } else {
            command.stdout(Stdio::null());
        }
        if !self.config.stderr.is_empty() {
            command.stderr(Stdio::piped());
        } else {
            command.stderr(Stdio::null());
        }

        let mut process = command.spawn()?;
        let pid = process.id();

        let (kill_tx, kill_rx) = oneshot::channel();

        // Update process state
        {
            let mut state = self.lock();
            state.started_at = Some(SystemTime::now());
            state.status = ProcessStatus::Running;
            state.pid = pid;
            state.kill_tx = Some(kill_tx);
            state.started = true;
        }

        // Handle IO redirection
        {
            let pidfile_path = self.config.pidfile.clone();
            if !pidfile_path.is_empty() {
                if let Err(err) =
                    fs_err::write(&pidfile_path, format!("{}", process.id().unwrap_or(0)))
                {
                    error!("Failed to write pidfile: {err}");
                }
            }

            let stdout = process.stdout.take();
            let stderr = process.stderr.take();
            let stdout_path = self.config.stdout.clone();
            let stderr_path = self.config.stderr.clone();

            if let Some(stdout) = stdout {
                tokio::spawn(redirect(stdout, stdout_path));
            }
            if let Some(stderr) = stderr {
                tokio::spawn(redirect(stderr, stderr_path));
            }
        }

        // Task for waiting on process
        {
            let process_uuid = self.config.id.clone();
            let weak_state = Arc::downgrade(&self.state);

            let span = tracing::info_span!("process", id = process_uuid);
            tokio::spawn(
                async move {
                    info!("Started");
                    let (killed, result) = wait_on_process(process, kill_rx).await;
                    let state = weak_state.upgrade();
                    let next_status = match result {
                        Ok(status) => {
                            if killed {
                                info!("Stopped");
                            } else if status.success() {
                                info!("Exited");
                            } else {
                                error!("Exited: {status:?}");
                            }
                            if killed {
                                ProcessStatus::Stopped
                            } else {
                                ProcessStatus::Exited(exit_code(status))
                            }
                        }
                        Err(e) => {
                            error!("Failed to wait on process: {e:?}");
                            ProcessStatus::Error(e.to_string())
                        }
                    };
                    if let Some(state) = state {
                        let mut state = state.lock().or_panic("lock should never fail");
                        state.status = next_status;
                        state.stopped_at = Some(SystemTime::now());
                    }
                }
                .instrument(span),
            );
        }

        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        let mut state = self.lock();
        state.started = false;
        let is_running = state.status.is_running();
        let Some(stop_tx) = state.kill_tx.take() else {
            if is_running {
                bail!("Missing kill tx for process");
            }
            return Ok(());
        };
        match stop_tx.send(()) {
            Ok(()) => Ok(()),
            Err(()) => match is_running {
                true => bail!("Failed to send stop signal to process"),
                false => Ok(()),
            },
        }
    }

    pub fn info(&self) -> ProcessInfo {
        let state = self.lock();
        ProcessInfo {
            config: (*self.config).clone(),
            state: state.display(),
        }
    }
}

#[cfg(unix)]
fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.into_raw()
}

#[cfg(not(unix))]
fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(0)
}

async fn wait_on_process(
    mut process: Child,
    kill_rx: oneshot::Receiver<()>,
) -> (bool, Result<ExitStatus>) {
    let (killed, result) = tokio::select! {
        _ = kill_rx => {
            info!("Killing process");
            if let Err(err) = process.kill().await {
                error!("Failed to kill process: {err:?}");
            }
            (true, process.wait().await)
        }
        result = process.wait() => {
            (false, result)
        }
    };
    if killed {
        info!("Killed");
    }
    (killed, result.map_err(Into::into))
}

async fn redirect(mut input: impl AsyncRead + Unpin, to: String) {
    async fn consume(input: &mut (impl AsyncRead + Unpin)) -> Result<()> {
        let mut buffer = [0u8; 2048];
        loop {
            let n = input.read(&mut buffer).await?;
            if n == 0 {
                return Ok(());
            }
        }
    }
    if let Err(e) = try_redirect(&mut input, to).await {
        error!("Failed to redirect process output: {e}");
    }
    if let Err(e) = consume(&mut input).await {
        error!("Failed to consume process output: {e}");
    }
}

async fn try_redirect(input: &mut (impl AsyncRead + Unpin), to: String) -> Result<()> {
    let dst_path = Path::new(&to);
    let dst_path_buf = dst_path.to_path_buf();
    let (reopen_tx, mut reopen_rx) = mpsc::channel(1);

    // Set up file system watcher for logrotate detection
    let mut watcher =
        notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                // Check if the event affects our specific file
                if (event.kind.is_remove() || event.kind.is_modify())
                    && event.paths.iter().any(|p| p == &dst_path_buf)
                {
                    let _ = reopen_tx.blocking_send(());
                }
            }
        })?;
    // Watch the log file's parent directory
    watcher.watch(
        dst_path.parent().unwrap_or(Path::new(".")),
        RecursiveMode::NonRecursive,
    )?;

    let mut buffer = [0u8; 8192];
    loop {
        // Open or reopen the log file in append mode
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dst_path)?;

        loop {
            tokio::select! {
                // Handle reopening signal
                _ = reopen_rx.recv() => {
                    // Sync file to ensure all data is written
                    if let Err(e) = file.sync_all() {
                        error!("Failed to sync log file: {e}");
                        break;
                    }
                    break; // Break inner loop to reopen file
                }
                // Read and write data
                result = input.read(&mut buffer) => {
                    match result {
                        Ok(0) => return Ok(()), // EOF
                        Ok(n) => {
                            if let Err(e) = file.write_all(&buffer[..n]) {
                                error!("Failed to write to log file: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Failed to read from process: {e}");
                            return Err(e.into());
                        }
                    }
                }
            }
        }
    }
}
