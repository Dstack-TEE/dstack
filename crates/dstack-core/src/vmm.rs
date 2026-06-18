// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! thin typed client over the VMM `Vmm` prpc service.
//!
//! talks to a local VMM over its unix control socket, or a remote VMM over an
//! http(s) endpoint. prpc calls go to `/prpc/<Method>?json`; a few endpoints
//! (e.g. `/logs`) are plain HTTP and are reached with [`http_client::http_request`].

use anyhow::{anyhow, bail, Result};
use dstack_vmm_rpc::vmm_client::VmmClient;
use dstack_vmm_rpc::{Id, StatusRequest, StatusResponse, VmConfiguration};
use http_client::http_request;
use http_client::prpc::PrpcClient;

/// default local VMM control socket (created by `dstackup install`).
pub const DEFAULT_HOST: &str = "unix:/var/run/dstack/vmm.sock";

/// a connection to a VMM — local unix socket or remote http endpoint.
pub struct Vmm {
    rpc: VmmClient<PrpcClient>,
    /// base string usable with [`http_request`] for non-prpc endpoints.
    base: String,
}

impl Vmm {
    /// connect to a VMM addressed by `host`:
    /// `unix:/path/to/vmm.sock` (local) or `http(s)://host:port` (remote).
    pub fn connect(host: &str) -> Result<Self> {
        let host = host.trim();
        if let Some(sock) = host.strip_prefix("unix:") {
            let rpc = VmmClient::new(PrpcClient::new_unix(sock.to_string(), "/prpc".to_string()));
            Ok(Self {
                rpc,
                base: format!("unix:{sock}"),
            })
        } else if host.starts_with("http://") || host.starts_with("https://") {
            let base = host.trim_end_matches('/').to_string();
            let rpc = VmmClient::new(PrpcClient::new(format!("{base}/prpc")));
            Ok(Self { rpc, base })
        } else {
            bail!(
                "unsupported host '{host}': expected unix:/path/to/vmm.sock or http(s)://host:port"
            );
        }
    }

    /// whether this connection targets a local unix socket.
    pub fn is_local(&self) -> bool {
        self.base.starts_with("unix:")
    }

    /// list deployed VMs (brief: no full configuration).
    pub async fn status(&self) -> Result<StatusResponse> {
        self.rpc
            .status(StatusRequest {
                brief: true,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("vmm Status rpc failed: {e}"))
    }

    /// compute the compose hash for a VM configuration (no side effects).
    /// the app id is the first 40 hex chars of this hash.
    pub async fn get_compose_hash(&self, cfg: &VmConfiguration) -> Result<String> {
        self.rpc
            .get_compose_hash(cfg.clone())
            .await
            .map(|c| c.hash)
            .map_err(|e| anyhow!("vmm GetComposeHash rpc failed: {e}"))
    }

    /// create (and, unless `cfg.stopped`, start) a VM; returns the new VM id.
    pub async fn create_vm(&self, cfg: VmConfiguration) -> Result<String> {
        self.rpc
            .create_vm(cfg)
            .await
            .map(|id| id.id)
            .map_err(|e| anyhow!("vmm CreateVm rpc failed: {e}"))
    }

    /// stop a VM by id, keeping its disk (so its keys survive a re-install).
    pub async fn stop_vm(&self, id: &str) -> Result<()> {
        self.rpc
            .stop_vm(Id { id: id.to_string() })
            .await
            .map_err(|e| anyhow!("vmm StopVm rpc failed: {e}"))
    }

    /// remove (and stop) a VM by id.
    pub async fn remove_vm(&self, id: &str) -> Result<()> {
        self.rpc
            .remove_vm(Id { id: id.to_string() })
            .await
            .map_err(|e| anyhow!("vmm RemoveVm rpc failed: {e}"))
    }

    /// whether a VM with the given id currently exists.
    pub async fn has_vm(&self, id: &str) -> bool {
        match self.status().await {
            Ok(s) => s.vms.iter().any(|v| v.id == id),
            Err(_) => false,
        }
    }

    /// fetch the last `lines` log lines for a VM (non-following).
    ///
    /// `/logs` is a plain-HTTP `GET` endpoint. Only the local unix-socket
    /// transport is wired today; remote `dstack logs` lands with the TLS+token
    /// transport (the shared http helper only `POST`s, and an unauthenticated
    /// remote log endpoint shouldn't be reachable before that exists).
    pub async fn logs(&self, id: &str, lines: u32) -> Result<String> {
        if !self.is_local() {
            bail!(
                "`dstack logs` over a remote endpoint isn't wired yet (lands with the \
                 TLS+token transport); use the local VMM socket for now"
            );
        }
        let path = format!("/logs?id={id}&follow=false&ansi=false&lines={lines}");
        let (status, body) = http_request("GET", &self.base, &path, b"").await?;
        if status != 200 {
            bail!("vmm /logs returned status {status}");
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}
