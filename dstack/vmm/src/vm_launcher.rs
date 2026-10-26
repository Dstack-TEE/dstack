// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::{
    errno::Errno,
    fcntl::{fcntl, FcntlArg, FdFlag},
    sys::{
        prctl,
        signal::{kill, raise, Signal},
    },
    unistd::{dup2, getpid, getppid, setpgid, Pid},
};
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

/// Descriptor a sidecar receives its end of a [`SidecarChannel::Socketpair`] as.
pub const SIDECAR_FD: i32 = 3;

/// A helper process QEMU talks to over a Unix socket, such as swtpm or passt.
/// It starts before QEMU and lives and dies with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub name: String,
    pub command: ChildCommand,
    pub channel: SidecarChannel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarChannel {
    /// The sidecar listens on this path; QEMU starts once it exists.
    Listen(PathBuf),
    /// The launcher connects the two over a socketpair: the sidecar gets its
    /// end as [`SIDECAR_FD`], QEMU gets the other end as this descriptor.
    Socketpair(i32),
}

impl Sidecar {
    fn listen_socket(&self) -> Option<&Path> {
        match &self.channel {
            SidecarChannel::Listen(path) => Some(path),
            SidecarChannel::Socketpair(_) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchSpec {
    pub qemu: ChildCommand,
    #[serde(default)]
    pub sidecars: Vec<Sidecar>,
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
                warn!(path = %self.0.display(), %error, "failed to clean up sidecar socket");
            }
        }
    }
}

/// Descriptors a child receives at fixed numbers.
struct InheritedFds {
    // Collision-free copies that `mappings` refers to. They must stay open
    // until the child has exec'd, and close when this leaves scope.
    _sources: Vec<OwnedFd>,
    mappings: Vec<(i32, i32)>,
}

fn inherit_fds(fds: &[(i32, OwnedFd)]) -> Result<InheritedFds> {
    let max_target = fds.iter().map(|(target, _)| *target).max().unwrap_or(2);
    let sources = fds
        .iter()
        .map(|(_, fd)| {
            let fd = fcntl(fd.as_raw_fd(), FcntlArg::F_DUPFD_CLOEXEC(max_target + 1))
                .context("failed to reserve inherited file descriptor")?;
            // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this process.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        })
        .collect::<Result<Vec<_>>>()?;
    let mappings = fds
        .iter()
        .zip(&sources)
        .map(|((target, _), source)| (*target, source.as_raw_fd()))
        .collect();
    Ok(InheritedFds {
        _sources: sources,
        mappings,
    })
}

fn open_files(files: &[OpenFile]) -> Result<Vec<(i32, OwnedFd)>> {
    files
        .iter()
        .map(|file| {
            let opened = fs_err::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&file.path)
                .with_context(|| format!("failed to open {}", file.path.display()))?;
            Ok((file.fd, OwnedFd::from(opened.into_parts().0)))
        })
        .collect()
}

fn prepare_child(expected_parent: libc::pid_t, mappings: &[(i32, i32)]) -> std::io::Result<()> {
    setpgid(Pid::from_raw(0), Pid::from_raw(0))?;
    prctl::set_pdeathsig(Signal::SIGKILL)?;
    if getppid().as_raw() != expected_parent {
        raise(Signal::SIGKILL)?;
    }
    for &(target, source) in mappings {
        if target < 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "open file target fd must be at least 3",
            ));
        }
        if source == target {
            fcntl(target, FcntlArg::F_SETFD(FdFlag::empty()))?;
        } else {
            dup2(source, target)?;
        }
    }
    Ok(())
}

fn spawn_child(spec: &ChildCommand, fds: &[(i32, OwnedFd)]) -> Result<Child> {
    let parent = getpid().as_raw();
    let mut command = Command::new(&spec.command);
    command.args(&spec.args);
    let inherited = inherit_fds(fds)?;
    let mappings = inherited.mappings.clone();
    // SAFETY: pre_exec only invokes async-signal-safe libc operations. Checking
    // the parent after PR_SET_PDEATHSIG closes the fork/parent-exit race.
    unsafe {
        command
            .as_std_mut()
            .pre_exec(move || prepare_child(parent, &mappings));
    }
    command
        .spawn()
        .with_context(|| format!("failed to start {}", spec.command))
}

fn exec_in_place(spec: &ChildCommand, fds: &[(i32, OwnedFd)]) -> Result<()> {
    let inherited = inherit_fds(fds)?;
    let parent = getppid().as_raw();
    prepare_child(parent, &inherited.mappings).context("failed to prepare in-place QEMU exec")?;
    let mut command = std::process::Command::new(&spec.command);
    command.args(&spec.args);
    let error = command.exec();
    Err(error).with_context(|| format!("failed to exec {}", spec.command))
}

async fn stop_child(child: &mut Child, name: &str, grace: Duration) {
    let Some(pid) = child.id() else {
        return;
    };
    if let Err(error) = kill(Pid::from_raw(-(pid as libc::pid_t)), Signal::SIGTERM) {
        if error != Errno::ESRCH {
            warn!(%pid, %name, %error, "failed to terminate child");
        }
    }
    match timeout(grace, child.wait()).await {
        Ok(Ok(status)) => info!(%pid, %name, %status, "child stopped"),
        Ok(Err(error)) => warn!(%pid, %name, %error, "failed to wait for child"),
        Err(_) => {
            warn!(%pid, %name, "child did not stop gracefully; killing");
            if let Err(error) = kill(Pid::from_raw(-(pid as libc::pid_t)), Signal::SIGKILL) {
                if error != Errno::ESRCH {
                    warn!(%pid, %name, %error, "failed to kill child process group");
                }
            }
            if let Err(error) = child.wait().await {
                warn!(%pid, %name, %error, "failed to reap killed child");
            }
        }
    }
}

struct RunningSidecar {
    name: String,
    child: Child,
}

async fn stop_sidecars(sidecars: &mut [RunningSidecar], grace: Duration) {
    for sidecar in sidecars.iter_mut().rev() {
        stop_child(&mut sidecar.child, &sidecar.name, grace).await;
    }
}

async fn wait_for_sockets(
    sidecars: &mut [RunningSidecar],
    specs: &[Sidecar],
    deadline: Instant,
) -> Result<()> {
    loop {
        for sidecar in sidecars.iter_mut() {
            if let Some(status) = sidecar.child.try_wait()? {
                bail!("{} exited during startup: {status}", sidecar.name);
            }
        }
        let pending = specs.iter().find_map(|spec| {
            spec.listen_socket()
                .filter(|socket| !socket.exists())
                .map(|socket| (&spec.name, socket))
        });
        let Some((name, socket)) = pending else {
            return Ok(());
        };
        if Instant::now() >= deadline {
            bail!("timed out waiting for {name} socket {}", socket.display());
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Starts a sidecar, handing it its end of a socketpair channel and keeping
/// the other end for QEMU.
fn spawn_sidecar(sidecar: &Sidecar, qemu_fds: &mut Vec<(i32, OwnedFd)>) -> Result<Child> {
    let mut fds = vec![];
    if let SidecarChannel::Socketpair(qemu_fd) = sidecar.channel {
        let (ours, theirs) = UnixStream::pair().context("failed to create sidecar socketpair")?;
        qemu_fds.push((qemu_fd, ours.into()));
        fds.push((SIDECAR_FD, theirs.into()));
    }
    spawn_child(&sidecar.command, &fds)
}

/// Resolves when any sidecar exits, reporting which one.
async fn wait_any_sidecar(
    sidecars: &mut [RunningSidecar],
) -> (String, std::io::Result<std::process::ExitStatus>) {
    let waits = sidecars
        .iter_mut()
        .map(|sidecar| Box::pin(async { (sidecar.name.clone(), sidecar.child.wait().await) }));
    futures::future::select_all(waits).await.0
}

pub async fn run(spec_path: &Path) -> Result<()> {
    let raw = fs_err::read(spec_path)
        .with_context(|| format!("failed to read launch spec {}", spec_path.display()))?;
    let spec: LaunchSpec = serde_json::from_slice(&raw).context("failed to parse launch spec")?;
    let mut qemu_fds = open_files(&spec.open_files)?;
    if spec.sidecars.is_empty() {
        return exec_in_place(&spec.qemu, &qemu_fds);
    }
    let mut socket_cleanup = vec![];
    for sidecar in &spec.sidecars {
        let Some(socket) = sidecar.listen_socket() else {
            continue;
        };
        socket_cleanup.push(SocketCleanup(socket.to_path_buf()));
        if socket.exists() {
            fs_err::remove_file(socket)
                .with_context(|| format!("failed to remove stale {} socket", sidecar.name))?;
        }
    }

    let grace = Duration::from_millis(spec.shutdown_timeout_ms);
    let mut terminate = signal(SignalKind::terminate()).context("failed to watch SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("failed to watch SIGINT")?;
    let mut sidecars = Vec::with_capacity(spec.sidecars.len());
    for sidecar in &spec.sidecars {
        match spawn_sidecar(sidecar, &mut qemu_fds) {
            Ok(child) => sidecars.push(RunningSidecar {
                name: sidecar.name.clone(),
                child,
            }),
            Err(error) => {
                stop_sidecars(&mut sidecars, grace).await;
                return Err(error);
            }
        }
    }
    enum StartupExit {
        Ready,
        Error(anyhow::Error),
        Signal,
    }
    let startup_exit = {
        let startup = wait_for_sockets(
            &mut sidecars,
            &spec.sidecars,
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
    };
    match startup_exit {
        StartupExit::Ready => {}
        StartupExit::Error(error) => {
            stop_sidecars(&mut sidecars, grace).await;
            return Err(error);
        }
        StartupExit::Signal => {
            stop_sidecars(&mut sidecars, grace).await;
            return Ok(());
        }
    }

    let qemu = spawn_child(&spec.qemu, &qemu_fds);
    // QEMU holds its own copies now. Keeping ours would hide QEMU's exit from
    // socketpair sidecars.
    drop(qemu_fds);
    let mut qemu = match qemu {
        Ok(child) => child,
        Err(error) => {
            stop_sidecars(&mut sidecars, grace).await;
            return Err(error);
        }
    };
    info!(
        qemu_pid = qemu.id(),
        sidecars = ?sidecars
            .iter()
            .map(|sidecar| (sidecar.name.as_str(), sidecar.child.id()))
            .collect::<Vec<_>>(),
        "VM processes started"
    );

    enum Exit {
        Signal,
        Qemu(std::process::ExitStatus),
        Sidecar(String, std::process::ExitStatus),
    }
    let exit = tokio::select! {
        _ = terminate.recv() => Exit::Signal,
        _ = interrupt.recv() => Exit::Signal,
        status = qemu.wait() => Exit::Qemu(status.context("failed to wait for QEMU")?),
        (name, status) = wait_any_sidecar(&mut sidecars) => {
            let status = status.with_context(|| format!("failed to wait for {name}"))?;
            Exit::Sidecar(name, status)
        }
    };

    let qemu_status = match exit {
        Exit::Signal => {
            stop_child(&mut qemu, "qemu", grace).await;
            stop_sidecars(&mut sidecars, grace).await;
            return Ok(());
        }
        Exit::Qemu(status) => status,
        Exit::Sidecar(name, status) => {
            // A socketpair sidecar exits cleanly once QEMU closes its end,
            // which can be observed before QEMU itself has been reaped.
            let qemu_exit = if status.success() {
                timeout(grace, qemu.wait()).await.ok().and_then(Result::ok)
            } else {
                None
            };
            match qemu_exit {
                Some(qemu_status) => qemu_status,
                None => {
                    error!(%name, %status, "sidecar exited while QEMU was running");
                    stop_child(&mut qemu, "qemu", grace).await;
                    stop_sidecars(&mut sidecars, grace).await;
                    bail!("{name} exited with {status}")
                }
            }
        }
    };
    stop_sidecars(&mut sidecars, grace).await;
    if qemu_status.success() {
        Ok(())
    } else {
        bail!("QEMU exited with {qemu_status}")
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
        matches!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH))
    }

    fn sidecar(command: ChildCommand, socket: PathBuf) -> Sidecar {
        Sidecar {
            name: "swtpm".into(),
            command,
            channel: SidecarChannel::Listen(socket),
        }
    }

    async fn create_fake_socket(path: PathBuf) {
        sleep(Duration::from_millis(100)).await;
        let _listener = UnixListener::bind(path).unwrap();
        sleep(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn passes_open_file_to_child() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let input = dir.path().join("input");
        let output = dir.path().join("output");
        fs_err::write(&input, b"macvtap-fd")?;
        let command = shell(format!("cat <&3 > {}", output.display()));
        let fds = open_files(&[OpenFile { fd: 3, path: input }])?;
        let mut child = spawn_child(&command, &fds)?;
        assert!(child.wait().await?.success());

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
            sidecars: vec![sidecar(
                shell(format!("echo $$ > {}; sleep 30", swtpm_pid.display())),
                socket.clone(),
            )],
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
            sidecars: vec![sidecar(shell("sleep 0.2; exit 9".into()), socket.clone())],
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
    async fn socketpair_connects_qemu_to_its_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let reply = dir.path().join("reply");
        let spec = LaunchSpec {
            qemu: shell(format!(
                "echo ping >&4; read reply <&4; echo \"$reply\" > {}",
                reply.display()
            )),
            sidecars: vec![Sidecar {
                name: "passt".into(),
                command: shell("read line <&3; echo \"pong $line\" >&3".into()),
                channel: SidecarChannel::Socketpair(4),
            }],
            open_files: vec![],
            startup_timeout_ms: 2_000,
            shutdown_timeout_ms: 500,
        };
        let spec_path = dir.path().join("spec.json");
        fs_err::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();

        // The sidecar exiting cleanly alongside QEMU is a normal shutdown.
        run(&spec_path).await.unwrap();
        assert_eq!(fs_err::read_to_string(reply).unwrap(), "pong ping\n");
    }

    #[tokio::test]
    async fn one_sidecar_failure_stops_qemu_and_the_other_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("swtpm.sock");
        let qemu_pid = dir.path().join("qemu.pid");
        let swtpm_pid = dir.path().join("swtpm.pid");
        let spec = LaunchSpec {
            qemu: shell(format!("echo $$ > {}; sleep 30", qemu_pid.display())),
            sidecars: vec![
                sidecar(
                    shell(format!("echo $$ > {}; sleep 30", swtpm_pid.display())),
                    socket.clone(),
                ),
                Sidecar {
                    name: "passt".into(),
                    command: shell("sleep 0.3; exit 1".into()),
                    channel: SidecarChannel::Socketpair(4),
                },
            ],
            open_files: vec![],
            startup_timeout_ms: 2_000,
            shutdown_timeout_ms: 500,
        };
        let spec_path = dir.path().join("spec.json");
        fs_err::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();
        tokio::spawn(create_fake_socket(socket.clone()));

        let error = run(&spec_path).await.unwrap_err();
        assert!(error.to_string().starts_with("passt exited"), "{error:#}");
        for pid_file in [qemu_pid, swtpm_pid] {
            let pid: libc::pid_t = fs_err::read_to_string(pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(process_is_gone(pid));
        }
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn startup_timeout_stops_swtpm_and_removes_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("swtpm.sock");
        let swtpm_pid = dir.path().join("swtpm.pid");
        let spec = LaunchSpec {
            qemu: shell("exit 0".into()),
            sidecars: vec![sidecar(
                shell(format!("echo $$ > {}; sleep 30", swtpm_pid.display())),
                socket.clone(),
            )],
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
            sidecars: vec![sidecar(
                shell(format!("echo $$ > {}; sleep 30", swtpm_pid.display())),
                socket.clone(),
            )],
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
            sidecars: vec![sidecar(
                ChildCommand {
                    command: dir.path().join("missing-swtpm").display().to_string(),
                    args: vec![],
                },
                socket.clone(),
            )],
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
