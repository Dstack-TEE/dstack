// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-vmm-top serve`: a hub that polls many VMMs and serves what it sees
//! to any number of TUIs.
//!
//! Why a hub and not just more `--node` flags: a VMM usually listens on a
//! unix socket only, its token is per node, and every watcher polling every
//! node multiplies load. A hub next to the VMMs reaches their sockets, holds
//! their tokens, polls each once, and hands out one URL with one token of its
//! own.
//!
//! It is read-only by construction: it serves snapshots and log tails, and
//! has no route that changes a VM. Handing someone the hub token lets them
//! watch, never stop.
//!
//! Routes (all `GET`):
//! - `/healthz`: `ok`, no auth.
//! - `/api/v1/nodes`: a [`Report`].
//! - `/api/v1/logs?node=&id=&ch=serial|stdout|stderr&lines=`: a log tail.

use crate::collector::{self, Update};
use crate::snapshot::{NodeSnapshot, Report};
use crate::source::{LogChannel, Source};
use anyhow::{bail, Context, Result};
use fs_err as fs;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

const MAX_LOG_LINES: u32 = 20_000;

pub struct Options {
    pub name: String,
    pub listen: String,
    pub token: Option<String>,
    pub interval_ms: u64,
    /// Serve without a token on a non-loopback address.
    pub insecure: bool,
}

struct Hub {
    name: String,
    interval_ms: u64,
    token: Option<String>,
    sources: Vec<Arc<Source>>,
    latest: RwLock<Vec<Vec<NodeSnapshot>>>,
}

pub async fn run(sources: Vec<Source>, opts: Options) -> Result<()> {
    if sources.is_empty() {
        bail!("nothing to serve: give --node, a config file, or run next to a VMM");
    }
    let listen = Listen::parse(&opts.listen)?;
    if opts.token.is_none() && !listen.is_local() && !opts.insecure {
        bail!(
            "refusing to serve {} without a token: set --auth-token (or DSTACK_VMM_TOP_TOKEN), \
             listen on loopback or a unix socket, or pass --insecure",
            opts.listen
        );
    }
    let sources: Vec<Arc<Source>> = sources.into_iter().map(Arc::new).collect();
    for s in &sources {
        info!("watching {} at {}", s.spec.name, s.endpoint());
    }
    let hub = Arc::new(Hub {
        name: opts.name,
        interval_ms: opts.interval_ms,
        token: opts.token,
        latest: RwLock::new(vec![Vec::new(); sources.len()]),
        sources: sources.clone(),
    });
    let mut handle = collector::spawn(sources, opts.interval_ms);
    let h = hub.clone();
    tokio::spawn(async move {
        while let Some(up) = handle.updates.recv().await {
            if let Update::Nodes { source, nodes } = up {
                for n in &nodes {
                    if let Some(e) = &n.error {
                        warn!("{}: {e}", n.name);
                    }
                }
                if let Ok(mut latest) = h.latest.write() {
                    latest[source] = nodes;
                }
            }
        }
    });

    match listen {
        Listen::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("failed to listen on {addr}"))?;
            info!("serving on http://{addr}");
            loop {
                let (stream, _) = listener.accept().await?;
                spawn_conn(TokioIo::new(stream), hub.clone());
            }
        }
        Listen::Unix(path) => {
            let _ = fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)
                .with_context(|| format!("failed to listen on {path}"))?;
            info!("serving on unix:{path}");
            loop {
                let (stream, _) = listener.accept().await?;
                spawn_conn(TokioIo::new(stream), hub.clone());
            }
        }
    }
}

fn spawn_conn<I>(io: I, hub: Arc<Hub>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let svc = service_fn(move |req| {
            let hub = hub.clone();
            async move { Ok::<_, std::convert::Infallible>(route(&hub, req).await) }
        });
        if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
            tracing::debug!("connection ended: {err}");
        }
    });
}

enum Listen {
    Tcp(SocketAddr),
    Unix(String),
}

impl Listen {
    fn parse(s: &str) -> Result<Self> {
        if let Some(path) = s.strip_prefix("unix:") {
            return Ok(Listen::Unix(path.to_string()));
        }
        Ok(Listen::Tcp(s.parse().with_context(|| {
            format!("invalid listen address '{s}': expected HOST:PORT or unix:PATH")
        })?))
    }

    fn is_local(&self) -> bool {
        match self {
            Listen::Tcp(a) => a.ip().is_loopback(),
            Listen::Unix(_) => true,
        }
    }
}

fn reply(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(body.into()));
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn text(status: StatusCode, body: impl Into<String>) -> Response<Full<Bytes>> {
    reply(status, "text/plain; charset=utf-8", body.into())
}

/// Equal without leaking where the first difference is.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn authorized(hub: &Hub, req: &Request<Incoming>) -> bool {
    let Some(token) = &hub.token else {
        return true;
    };
    let Some(header) = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    match header.strip_prefix("Bearer ") {
        Some(given) => ct_eq(given.trim().as_bytes(), token.as_bytes()),
        None => false,
    }
}

async fn route(hub: &Hub, req: Request<Incoming>) -> Response<Full<Bytes>> {
    if req.method() != hyper::Method::GET {
        return text(StatusCode::METHOD_NOT_ALLOWED, "read-only hub: GET only");
    }
    let path = req.uri().path().to_string();
    if path == "/healthz" {
        return text(StatusCode::OK, "ok");
    }
    if !authorized(hub, &req) {
        return text(StatusCode::UNAUTHORIZED, "missing or wrong bearer token");
    }
    let query = parse_query(req.uri().query().unwrap_or(""));
    match path.as_str() {
        "/api/v1/nodes" => {
            let report = Report {
                hub: hub.name.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                interval_ms: hub.interval_ms,
                nodes: served(hub).into_iter().map(|(n, _, _)| n).collect(),
            };
            match serde_json::to_vec(&report) {
                Ok(body) => reply(StatusCode::OK, "application/json", body),
                Err(err) => text(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            }
        }
        "/api/v1/logs" => logs(hub, &query).await,
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Every node with the name it is served under, its source, and the name the
/// source knows it by. Names stay as the source gave them unless two sources
/// collide, which happens when hubs are chained.
fn served(hub: &Hub) -> Vec<(NodeSnapshot, usize, String)> {
    let latest = hub.latest.read().map(|l| l.clone()).unwrap_or_default();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (si, nodes) in latest.into_iter().enumerate() {
        for mut n in nodes {
            let orig = n.name.clone();
            if !seen.insert(n.name.clone()) {
                n.name = format!("{}/{orig}", hub.sources[si].spec.name);
                seen.insert(n.name.clone());
            }
            out.push((n, si, orig));
        }
    }
    out
}

async fn logs(hub: &Hub, q: &HashMap<String, String>) -> Response<Full<Bytes>> {
    let (Some(node), Some(id)) = (q.get("node"), q.get("id")) else {
        return text(StatusCode::BAD_REQUEST, "node and id are required");
    };
    let c = q.get("ch").map(String::as_str).unwrap_or("serial");
    let Some(ch) = LogChannel::parse(c) else {
        return text(StatusCode::BAD_REQUEST, format!("unknown channel {c}"));
    };
    let lines = q
        .get("lines")
        .and_then(|l| l.parse::<u32>().ok())
        .unwrap_or(1000)
        .min(MAX_LOG_LINES);
    let Some((snap, si, orig)) = served(hub).into_iter().find(|(n, _, _)| &n.name == node) else {
        return text(StatusCode::NOT_FOUND, format!("no node {node}"));
    };
    // Only VMs the node listed: an id is never passed through unchecked.
    if !snap.vms.iter().any(|v| &v.id == id) {
        return text(StatusCode::NOT_FOUND, format!("no VM {id} on {node}"));
    }
    match hub.sources[si].logs(&orig, id, ch, lines).await {
        Ok(body) => text(StatusCode::OK, body),
        Err(err) => text(StatusCode::BAD_GATEWAY, format!("{err:#}")),
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::query_escape;

    #[test]
    fn query_round_trips() {
        let q = parse_query(&format!(
            "node={}&id={}&lines=5",
            query_escape("dc/tdx 01"),
            query_escape("a&b")
        ));
        assert_eq!(q["node"], "dc/tdx 01");
        assert_eq!(q["id"], "a&b");
        assert_eq!(q["lines"], "5");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
    }

    #[test]
    fn token_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn listen_locality() {
        assert!(Listen::parse("127.0.0.1:9970").unwrap().is_local());
        assert!(Listen::parse("unix:/tmp/x.sock").unwrap().is_local());
        assert!(!Listen::parse("0.0.0.0:9970").unwrap().is_local());
        assert!(Listen::parse("nope").is_err());
    }
}
