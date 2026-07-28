// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use http_client::http_request;
use log::{error, info};
use supervisor::{ProcessConfig, ProcessInfo, Response};

pub use supervisor;

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn trusted_uds_identity(path: &Path) -> Result<SocketIdentity> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let metadata = fs_err::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect supervisor socket {}", path.display()))?;
    if !metadata.file_type().is_socket() {
        anyhow::bail!(
            "Supervisor endpoint is not a Unix socket: {}",
            path.display()
        );
    }
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        anyhow::bail!("Supervisor socket is not owned by the current user");
    }
    if metadata.mode() & 0o022 != 0 {
        anyhow::bail!("Supervisor socket is writable by another user");
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs_err::symlink_metadata(parent).with_context(|| {
        format!(
            "Failed to inspect supervisor socket directory {}",
            parent.display()
        )
    })?;
    if !parent_metadata.file_type().is_dir() {
        anyhow::bail!("Supervisor socket parent is not a directory");
    }
    let parent_owned = parent_metadata.uid() == effective_uid;
    let parent_sticky = parent_metadata.mode() & 0o1000 != 0;
    if !parent_owned && !parent_sticky {
        anyhow::bail!("Supervisor socket directory is not controlled by the current user");
    }
    if parent_metadata.mode() & 0o022 != 0 && !parent_sticky {
        anyhow::bail!("Supervisor socket directory permits untrusted replacement");
    }

    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn acquire_uds_start_lock(uds: &Path) -> Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let lock_path = uds.with_extension("lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "Failed to open Supervisor start lock {}",
                lock_path.display()
            )
        })?;
    let metadata = lock.metadata()?;
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
        anyhow::bail!("Supervisor start lock is not owner-only");
    }
    let result = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("Failed to lock Supervisor startup");
    }
    Ok(lock)
}

#[derive(Debug, Clone)]
pub struct SupervisorClient {
    base_url: Arc<String>,
}

impl SupervisorClient {
    pub fn new(base_url: &str) -> Self {
        SupervisorClient {
            base_url: Arc::new(base_url.to_string()),
        }
    }

    pub async fn start_and_connect_uds(
        supervisor_path: impl AsRef<Path>,
        uds: impl AsRef<Path>,
        pid_file: impl AsRef<Path>,
        log_file: impl AsRef<Path>,
        detached: bool,
        auto_start: bool,
    ) -> Result<Self> {
        let uds = uds.as_ref();
        let uri = format!("unix:{}", uds.display());
        let client = Self::new(&uri);
        if fs_err::symlink_metadata(uds).is_ok() {
            let identity = trusted_uds_identity(uds)?;
            if client.probe(Duration::from_millis(100)).await.is_ok()
                && trusted_uds_identity(uds)? == identity
            {
                info!("Connected to supervisor at {uri}");
                return Ok(client);
            }
        }
        if !auto_start {
            anyhow::bail!("Failed to connect to supervisor at {uri}");
        }
        info!("Failed to connect to supervisor at {uri}, trying to start supervisor");
        let _start_lock = acquire_uds_start_lock(uds)?;
        // Another process may have completed startup while this process waited
        // for the lock. Re-probe before treating the endpoint as stale.
        if fs_err::symlink_metadata(uds).is_ok() {
            let identity = trusted_uds_identity(uds)?;
            if client.probe(Duration::from_millis(500)).await.is_ok()
                && trusted_uds_identity(uds)? == identity
            {
                info!("Connected to supervisor at {uri} after waiting for startup lock");
                return Ok(client);
            }
        }
        if fs_err::symlink_metadata(uds).is_ok() {
            // Validate again immediately before removing a stale endpoint. Never
            // delete a path that is not a trusted socket owned by this user.
            trusted_uds_identity(uds)?;
            fs_err::remove_file(uds)?;
        }
        let supervisor_path = supervisor_path.as_ref().to_path_buf();
        let uds = uds.to_path_buf();
        let supervisor_uds = uds.clone();
        let pid_file = pid_file.as_ref().to_path_buf();
        let log_file = log_file.as_ref().to_path_buf();
        std::thread::spawn(move || {
            // start supervisor
            let result = std::process::Command::new(supervisor_path)
                .arg("--uds")
                .arg(supervisor_uds)
                .arg("--pid-file")
                .arg(pid_file)
                .arg("--log-file")
                .arg(log_file)
                .args(if detached { &["--detach"][..] } else { &[] })
                .env("RUST_LOG", "info,rocket=warn")
                .output();
            let output = match result {
                Ok(output) => output,
                Err(err) => {
                    error!("Failed to start supervisor: {err}");
                    return;
                }
            };
            if !output.status.success() {
                error!(
                    "Supervisor exited with error: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        });
        // wait while ping returns pong
        for i in 1..=10 {
            if let Ok(identity) = trusted_uds_identity(&uds) {
                if client.probe(Duration::from_millis(100)).await.is_ok()
                    && trusted_uds_identity(&uds).ok() == Some(identity)
                {
                    info!("connected to supervisor at {uri}");
                    return Ok(client);
                }
            }
            info!("waiting for supervisor at {uri} to start, attempt {i}");
            tokio::time::sleep(Duration::from_millis(100 * i)).await;
        }
        anyhow::bail!("failed to connect to supervisor at {uri}");
    }

    async fn http_request<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        path: &str,
        body: B,
    ) -> Result<T> {
        let body_bytes = match method {
            "POST" | "PUT" | "PATCH" => serde_json::to_vec(&body)?,
            _ => vec![],
        };
        let (status, response_bytes) =
            http_request(method, &self.base_url, path, &body_bytes).await?;
        if status != 200 {
            anyhow::bail!("Server returned error: {}", status);
        }
        let response: Response<T> =
            serde_json::from_slice(&response_bytes).context("Failed to parse response")?;
        response.into_result().context("Server returned error")
    }

    async fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.http_request("GET", path, ()).await
    }
}

// Async API
impl SupervisorClient {
    pub async fn deploy(&self, config: &ProcessConfig) -> Result<()> {
        self.http_request("POST", "/deploy", config).await
    }

    pub async fn start(&self, id: &str) -> Result<()> {
        self.http_request("POST", &format!("/start/{}", id), ())
            .await
    }

    pub async fn stop(&self, id: &str) -> Result<()> {
        self.http_request("POST", &format!("/stop/{}", id), ())
            .await
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        self.http_request("DELETE", &format!("/remove/{}", id), ())
            .await
    }

    pub async fn list(&self) -> Result<Vec<ProcessInfo>> {
        self.http_get("/list").await
    }

    pub async fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        self.http_get(&format!("/info/{}", id)).await
    }

    pub async fn ping(&self) -> Result<String> {
        self.http_get("/ping").await
    }

    pub async fn probe(&self, timeout: Duration) -> Result<()> {
        let response = tokio::time::timeout(timeout, self.ping()).await;
        if matches!(response, Ok(Ok(_))) {
            Ok(())
        } else {
            anyhow::bail!("failed to probe supervisor")
        }
    }

    pub async fn clear(&self) -> Result<()> {
        self.http_request("POST", "/clear", ()).await
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.http_request("POST", "/shutdown", ()).await
    }
}

#[derive(Debug, Clone)]
pub struct SupervisorClientSync {
    client: SupervisorClient,
}

impl From<SupervisorClient> for SupervisorClientSync {
    fn from(client: SupervisorClient) -> Self {
        SupervisorClientSync { client }
    }
}

// Sync API
impl SupervisorClientSync {
    fn http_request<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        path: &str,
        body: B,
    ) -> Result<T> {
        futures::executor::block_on(async move {
            tokio::time::timeout(
                Duration::from_millis(1000),
                self.client.http_request(method, path, body),
            )
            .await?
        })
    }

    fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.http_request("GET", path, ())
    }

    pub fn deploy(&self, config: ProcessConfig) -> Result<()> {
        self.http_request("POST", "/deploy", config)
    }

    pub fn start(&self, id: &str) -> Result<()> {
        self.http_request("POST", &format!("/start/{}", id), ())
    }

    pub fn stop(&self, id: &str) -> Result<()> {
        self.http_request("POST", &format!("/stop/{}", id), ())
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        self.http_request("DELETE", &format!("/remove/{}", id), ())
    }

    pub fn list(&self) -> Result<Vec<ProcessInfo>> {
        self.http_get("/list")
    }

    pub fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        self.http_get(&format!("/info/{}", id))
    }

    pub fn ping(&self) -> Result<String> {
        self.http_get("/ping")
    }

    pub fn probe(&self) -> Result<()> {
        if self.ping().is_ok() {
            Ok(())
        } else {
            anyhow::bail!("failed to probe supervisor")
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    #[test]
    fn trusted_uds_rejects_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("supervisor.sock");
        fs_err::write(&path, b"not a socket").unwrap();
        assert!(trusted_uds_identity(&path).is_err());
    }

    #[test]
    fn trusted_uds_accepts_owner_only_socket() {
        let directory = tempfile::tempdir().unwrap();
        fs_err::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("supervisor.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        fs_err::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        trusted_uds_identity(&path).expect("owner-only socket should be trusted");
    }

    #[test]
    fn trusted_uds_rejects_socket_writable_by_others() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("supervisor.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        fs_err::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(trusted_uds_identity(&path).is_err());
    }
}
