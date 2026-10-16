// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Where snapshots come from: a VMM, polled over its pRPC API and `/logs`,
//! at a base address (`unix:` socket or `http(s)://`) with an optional bearer
//! token.

use crate::snapshot::{Gpu, NodeSnapshot, Resources, Vm};
use anyhow::{anyhow, bail, Result};
use dstack_vmm_rpc::vmm_client::VmmClient;
use dstack_vmm_rpc::StatusRequest;
use http_client::http_request_with_headers;
use http_client::prpc::PrpcClient;
use std::time::{Duration, Instant};

/// Bound on one poll or one request, so a hung node shows as an error instead
/// of freezing its row.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Debug)]
pub struct SourceSpec {
    pub name: String,
    /// `unix:/path/to/vmm.sock` or `http(s)://host:port`.
    pub url: String,
    pub token: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogChannel {
    Serial,
    Stdout,
    Stderr,
}

impl LogChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogChannel::Serial => "serial",
            LogChannel::Stdout => "stdout",
            LogChannel::Stderr => "stderr",
        }
    }
}

pub struct Source {
    pub spec: SourceSpec,
    /// Base for plain-HTTP requests: `unix:/path` or `http(s)://host:port`.
    base: String,
    rpc: VmmClient<PrpcClient>,
}

impl Source {
    pub fn new(spec: SourceSpec) -> Result<Self> {
        let url = spec.url.trim();
        let base = if let Some(sock) = url.strip_prefix("unix:") {
            format!("unix:{sock}")
        } else if url.starts_with("http://") || url.starts_with("https://") {
            url.trim_end_matches('/').to_string()
        } else {
            bail!("unsupported address '{url}': expected unix:/path/to/vmm.sock or http(s)://host:port");
        };
        let client = match base.strip_prefix("unix:") {
            Some(sock) => PrpcClient::new_unix(sock.to_string(), "/prpc".to_string()),
            None => PrpcClient::new(format!("{base}/prpc")),
        };
        let client = client.with_request_timeout(REQUEST_TIMEOUT);
        let client = match &spec.token {
            Some(token) => client.with_bearer_token(token.clone()),
            None => client,
        };
        let rpc = VmmClient::new(client);
        Ok(Self { spec, base, rpc })
    }

    /// The address shown on screen: never carries credentials.
    pub fn endpoint(&self) -> String {
        display_endpoint(&self.base)
    }

    /// Poll every node behind this source once.
    pub async fn poll(&self) -> Result<Vec<NodeSnapshot>> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            Ok(vec![self.poll_vmm(&self.rpc).await?])
        })
        .await
        .map_err(|_| anyhow!("timed out after {}s", REQUEST_TIMEOUT.as_secs()))?
    }

    async fn poll_vmm(&self, rpc: &VmmClient<PrpcClient>) -> Result<NodeSnapshot> {
        let started = Instant::now();
        let status = rpc
            .status(StatusRequest::default())
            .await
            .map_err(|err| anyhow!("{err}"))?;
        let latency = started.elapsed();
        // Everything past the VM list is context: a VMM too old to answer
        // one of these still shows its VMs.
        let (version, meta, gpus) = tokio::join!(rpc.version(), rpc.get_meta(), rpc.list_gpus());
        let mut node = NodeSnapshot {
            name: self.spec.name.clone(),
            endpoint: self.endpoint(),
            latency_ms: Some(latency.as_millis() as u64),
            vms: status.vms.into_iter().map(Vm::from).collect(),
            ..Default::default()
        };
        if let Ok(v) = version {
            node.version = Some(v.version);
            node.rev = Some(v.rev).filter(|r| !r.is_empty());
        }
        if let Ok(meta) = meta {
            node.resources = meta.resources.map(|r| Resources {
                max_cvms: r.max_cvm_number,
                max_vcpu: r.max_allocable_vcpu,
                max_memory_mb: r.max_allocable_memory_in_mb,
            });
            if let Some(kms) = meta.kms {
                node.kms_urls = if kms.urls.is_empty() && !kms.url.is_empty() {
                    vec![kms.url]
                } else {
                    kms.urls
                };
            }
            if let Some(gw) = meta.gateway {
                node.gateway_urls = if gw.urls.is_empty() && !gw.url.is_empty() {
                    vec![gw.url]
                } else {
                    gw.urls
                };
                node.base_domain = Some(gw.base_domain).filter(|d| !d.is_empty());
            }
        }
        if let Ok(gpus) = gpus {
            node.gpus = gpus
                .gpus
                .into_iter()
                .map(|g| Gpu {
                    slot: g.slot,
                    product_id: g.product_id,
                    description: g.description,
                    is_free: g.is_free,
                })
                .collect();
        }
        Ok(node)
    }

    /// The last `lines` lines of one VM log channel.
    pub async fn logs(&self, vm_id: &str, ch: LogChannel, lines: u32) -> Result<String> {
        let path = format!(
            "/logs?id={}&follow=false&ansi=false&lines={lines}&ch={}",
            query_escape(vm_id),
            ch.as_str()
        );
        let body = self.get(&path).await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let auth = self.spec.token.as_ref().map(|t| format!("Bearer {t}"));
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(auth) = &auth {
            headers.push(("Authorization", auth));
        }
        let (status, body) = tokio::time::timeout(
            REQUEST_TIMEOUT,
            http_request_with_headers("GET", &self.base, path, b"", &headers),
        )
        .await
        .map_err(|_| anyhow!("timed out after {}s", REQUEST_TIMEOUT.as_secs()))??;
        if status != 200 {
            let text = String::from_utf8_lossy(&body);
            let text = text.trim();
            if text.is_empty() {
                bail!("HTTP {status}");
            }
            bail!("HTTP {status}: {}", crate::fmt::truncate(text, 160));
        }
        Ok(body)
    }
}

/// `base` with any `user:pass@` removed.
pub fn display_endpoint(base: &str) -> String {
    if let Some((scheme, rest)) = base.split_once("://") {
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        format!("{scheme}://{host}{path}")
    } else {
        base.to_string()
    }
}

/// Percent-encode everything outside RFC 3986 unreserved characters.
pub fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_hides_credentials() {
        assert_eq!(
            display_endpoint("https://u:p@host:9080/x"),
            "https://host:9080/x"
        );
        assert_eq!(display_endpoint("http://host:9080"), "http://host:9080");
        assert_eq!(display_endpoint("unix:/run/vmm.sock"), "unix:/run/vmm.sock");
    }

    #[test]
    fn query_escape_is_strict() {
        assert_eq!(query_escape("a b/c&d"), "a%20b%2Fc%26d");
        assert_eq!(query_escape("tdx-01_x.y~"), "tdx-01_x.y~");
    }

    #[test]
    fn rejects_unknown_scheme() {
        let spec = SourceSpec {
            name: "x".into(),
            url: "ftp://x".into(),
            token: None,
        };
        assert!(Source::new(spec).is_err());
    }
}
