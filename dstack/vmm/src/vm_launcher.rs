// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{sleep, timeout, Instant};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildCommand {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchSpec {
    pub qemu: ChildCommand,
    #[serde(default)]
    pub swtpm: Option<ChildCommand>,
    #[serde(default)]
    pub swtpm_socket: Option<PathBuf>,
    #[serde(default)]
    pub open_files: Vec<OpenFile>,
    #[serde(default = "default_startup_timeout_ms")]
    pub startup_timeout_ms: u64,
    #[serde(default = "default_shutdown_timeout_ms")]
    pub shutdown_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFile {
    pub fd: i32,
    pub path: PathBuf,
}

fn default_startup_timeout_ms() -> u64 {
    5_000
}

fn default_shutdown_timeout_ms() -> u64 {
    10_000
}

struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if self.0.exists() {
            if let Err(error) = fs_err::remove_file(&self.0) {
                warn!(path = %self.0.display(), %error, "failed to clean up swtpm socket");
            }
        }
    }
}

fn spawn_child(spec: &ChildCommand, open_files: &[OpenFile]) -> Result<Child> {
    let parent = unsafe { libc::getpid() };
    let mut command = Command::new(&spec.command);
    command.args(&spec.args);
    let opened = open_files
        .iter()
        .map(|file| {
            fs_err::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&file.path)
                .with_context(|| format!("failed to open {}", file.path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let max_target = open_files.iter().map(|file| file.fd).max().unwrap_or(2);
    let inherited = opened
        .iter()
        .map(|file| {
            let fd =
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, max_target + 1) };
            if fd < 0 {
                Err(std::io::Error::last_os_error())
                    .context("failed to reserve inherited file descriptor")
            } else {
                // SAFETY: fcntl returned a new descriptor owned by this process.
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let fds = open_files
        .iter()
        .zip(&inherited)
        .map(|(file, opened)| (file.fd, opened.as_raw_fd()))
        .collect::<Vec<_>>();
    // SAFETY: pre_exec only invokes async-signal-safe libc operations. Checking
    // the parent after PR_SET_PDEATHSIG closes the fork/parent-exit race.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::raise(libc::SIGKILL);
            }
            for &(target, source) in &fds {
                if target < 3 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "open file target fd must be at least 3",
                    ));
                }
                if source == target {
                    if libc::fcntl(target, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command
        .spawn()
        .with_context(|| format!("failed to start {}", spec.command))
}

async fn stop_child(child: &mut Child, name: &str, grace: Duration) {
    let Some(pid) = child.id() else {
        return;
    };
    // SAFETY: pid comes from the live Child handle and SIGTERM has no pointer arguments.
    if unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGTERM) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            warn!(%pid, %name, %error, "failed to terminate child");
        }
    }
    match timeout(grace, child.wait()).await {
        Ok(Ok(status)) => info!(%pid, %name, %status, "child stopped"),
        Ok(Err(error)) => warn!(%pid, %name, %error, "failed to wait for child"),
        Err(_) => {
            warn!(%pid, %name, "child did not stop gracefully; killing");
            if unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    warn!(%pid, %name, %error, "failed to kill child process group");
                }
            }
            if let Err(error) = child.wait().await {
                warn!(%pid, %name, %error, "failed to reap killed child");
            }
        }
    }
}

async fn wait_for_swtpm(swtpm: &mut Child, socket: &Path, deadline: Instant) -> Result<()> {
    loop {
        if socket.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for swtpm socket {}", socket.display());
        }
        tokio::select! {
            status = swtpm.wait() => {
                bail!("swtpm exited before socket was ready: {}", status?);
            }
            _ = sleep(Duration::from_millis(50)) => {}
        }
    }
}

pub async fn run(spec_path: &Path) -> Result<()> {
    let raw = fs_err::read(spec_path)
        .with_context(|| format!("failed to read launch spec {}", spec_path.display()))?;
    let spec: LaunchSpec = serde_json::from_slice(&raw).context("failed to parse launch spec")?;
    let _socket_cleanup = spec.swtpm_socket.clone().map(SocketCleanup);
    if let Some(socket) = &spec.swtpm_socket {
        if socket.exists() {
            fs_err::remove_file(socket).context("failed to remove stale swtpm socket")?;
        }
    }

    let grace = Duration::from_millis(spec.shutdown_timeout_ms);
    let mut terminate = signal(SignalKind::terminate()).context("failed to watch SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("failed to watch SIGINT")?;
    let mut swtpm = if let Some(command) = &spec.swtpm {
        Some(spawn_child(command, &[])?)
    } else {
        None
    };
    enum StartupExit {
        Ready,
        Error(anyhow::Error),
        Signal,
    }
    let startup_exit = if let (Some(swtpm), Some(socket)) = (&mut swtpm, &spec.swtpm_socket) {
        let startup = wait_for_swtpm(
            swtpm,
            socket,
            Instant::now() + Duration::from_millis(spec.startup_timeout_ms),
        );
        tokio::pin!(startup);
        tokio::select! {
            result = &mut startup => match result {
                Ok(()) => StartupExit::Ready,
                Err(error) => StartupExit::Error(error),
            },
            _ = terminate.recv() => StartupExit::Signal,
            _ = interrupt.recv() => StartupExit::Signal,
        }
    } else {
        StartupExit::Ready
    };
    match startup_exit {
        StartupExit::Ready => {}
        StartupExit::Error(error) => {
            if let Some(child) = &mut swtpm {
                stop_child(child, "swtpm", grace).await;
            }
            return Err(error);
        }
        StartupExit::Signal => {
            if let Some(child) = &mut swtpm {
                stop_child(child, "swtpm", grace).await;
            }
            return Ok(());
        }
    }

    let mut qemu = match spawn_child(&spec.qemu, &spec.open_files) {
        Ok(child) => child,
        Err(error) => {
            if let Some(child) = &mut swtpm {
                stop_child(child, "swtpm", grace).await;
            }
            return Err(error);
        }
    };
    info!(
        qemu_pid = qemu.id(),
        swtpm_pid = swtpm.as_ref().and_then(|child| child.id()),
        "VM processes started"
    );

    enum Exit {
        Signal,
        Qemu(std::process::ExitStatus),
        Swtpm(std::process::ExitStatus),
    }
    let exit = tokio::select! {
        _ = terminate.recv() => Exit::Signal,
        _ = interrupt.recv() => Exit::Signal,
        status = qemu.wait() => Exit::Qemu(status.context("failed to wait for QEMU")?),
        status = async {
            match &mut swtpm {
                Some(child) => child.wait().await,
                None => std::future::pending().await,
            }
        } => Exit::Swtpm(status.context("failed to wait for swtpm")?),
    };

    match exit {
        Exit::Signal => {
            stop_child(&mut qemu, "qemu", grace).await;
            if let Some(child) = &mut swtpm {
                stop_child(child, "swtpm", grace).await;
            }
            Ok(())
        }
        Exit::Qemu(status) => {
            if let Some(child) = &mut swtpm {
                stop_child(child, "swtpm", grace).await;
            }
            if status.success() {
                Ok(())
            } else {
                bail!("QEMU exited with {status}")
            }
        }
        Exit::Swtpm(status) => {
            error!(%status, "swtpm exited while QEMU was running");
            stop_child(&mut qemu, "qemu", grace).await;
            bail!("swtpm exited with {status}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn shell(script: String) -> ChildCommand {
        ChildCommand {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), script],
        }
    }

    fn process_is_gone(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only probes whether the PID still exists.
        let missing = unsafe { libc::kill(pid, 0) != 0 };
        missing && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    async fn create_fake_socket(path: PathBuf) {
        sleep(Duration::from_millis(100)).await;
        let _listener = UnixListener::bind(path).unwrap();
        sleep(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn passes_open_file_to_qemu_without_swtpm() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let input = dir.path().join("input");
        let output = dir.path().join("output");
        fs_err::write(&input, b"macvtap-fd")?;
        let spec_path = dir.path().join("spec.json");
        let spec = LaunchSpec {
            qemu: shell(format!("cat <&3 > {}", output.display())),
            swtpm: None,
            swtpm_socket: None,
            open_files: vec![OpenFile { fd: 3, path: input }],
            startup_timeout_ms: 1_000,
            shutdown_timeout_ms: 1_000,
        };
        fs_err::write(&spec_path, serde_json::to_vec(&spec)?)?;

        run(&spec_path).await?;

        assert_eq!(fs_err::read(output)?, b"macvtap-fd");
        Ok(())
    }

    #[tokio::test]
    async fn qemu_failure_stops_and_reaps_swtpm() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("swtpm.sock");
        let swtpm_pid = dir.path().join("swtpm.pid");
        let spec = LaunchSpec {
            qemu: shell("exit 7".into()),
            swtpm: Some(shell(format!(
                "echo $$ > {}; sleep 30",
                swtpm_pid.display()
            ))),
            swtpm_socket: Some(socket.clone()),
            open_files: vec![],
            startup_timeout_ms: 2_000,
            shutdown_timeout_ms: 500,
        };
        let spec_path = dir.path().join("spec.json");
        fs_err::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();
        tokio::spawn(create_fake_socket(socket));

        assert!(run(&spec_path).await.is_err());
        let pid: libc::pid_t = fs_err::read_to_string(swtpm_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(process_is_gone(pid));
    }

    #[tokio::test]
    async fn swtpm_failure_stops_and_reaps_qemu() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("swtpm.sock");
        let qemu_pid = dir.path().join("qemu.pid");
        let spec = LaunchSpec {
            qemu: shell(format!("echo $$ > {}; sleep 30", qemu_pid.display())),
            swtpm: Some(shell("sleep 0.2; exit 9".into())),
            swtpm_socket: Some(socket.clone()),
            open_files: vec![],
            startup_timeout_ms: 2_000,
            shutdown_timeout_ms: 500,
        };
        let spec_path = dir.path().join("spec.json");
        fs_err::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();
        tokio::spawn(create_fake_socket(socket));

        assert!(run(&spec_path).await.is_err());
        let pid: libc::pid_t = fs_err::read_to_string(qemu_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(process_is_gone(pid));
    }

    #[tokio::test]
    async fn startup_timeout_stops_swtpm_and_removes_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("swtpm.sock");
        let swtpm_pid = dir.path().join("swtpm.pid");
        let spec = LaunchSpec {
            qemu: shell("exit 0".into()),
            swtpm: Some(shell(format!(
                "echo $$ > {}; sleep 30",
                swtpm_pid.display()
            ))),
            swtpm_socket: Some(socket.clone()),
            open_files: vec![],
            startup_timeout_ms: 100,
            shutdown_timeout_ms: 500,
        };
        let spec_path = dir.path().join("spec.json");
        fs_err::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();

        assert!(run(&spec_path).await.is_err());
        let pid: libc::pid_t = fs_err::read_to_string(swtpm_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(process_is_gone(pid));
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn successful_qemu_exit_stops_swtpm_and_cleans_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("swtpm.sock");
        let swtpm_pid = dir.path().join("swtpm.pid");
        let spec = LaunchSpec {
            qemu: shell("sleep 0.1; exit 0".into()),
            swtpm: Some(shell(format!(
                "echo $$ > {}; sleep 30",
                swtpm_pid.display()
            ))),
            swtpm_socket: Some(socket.clone()),
            open_files: vec![],
            startup_timeout_ms: 2_000,
            shutdown_timeout_ms: 500,
        };
        let spec_path = dir.path().join("spec.json");
        fs_err::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();
        tokio::spawn(create_fake_socket(socket.clone()));

        assert!(run(&spec_path).await.is_ok());
        let pid: libc::pid_t = fs_err::read_to_string(swtpm_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(process_is_gone(pid));
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn swtpm_spawn_failure_removes_stale_socket_without_starting_qemu() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("swtpm.sock");
        fs_err::write(&socket, b"stale").unwrap();
        let qemu_marker = dir.path().join("qemu-started");
        let spec = LaunchSpec {
            qemu: shell(format!("touch {}", qemu_marker.display())),
            swtpm: Some(ChildCommand {
                command: dir.path().join("missing-swtpm").display().to_string(),
                args: vec![],
            }),
            swtpm_socket: Some(socket.clone()),
            open_files: vec![],
            startup_timeout_ms: 100,
            shutdown_timeout_ms: 100,
        };
        let spec_path = dir.path().join("spec.json");
        fs_err::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();

        assert!(run(&spec_path).await.is_err());
        assert!(!socket.exists());
        assert!(!qemu_marker.exists());
    }
}
