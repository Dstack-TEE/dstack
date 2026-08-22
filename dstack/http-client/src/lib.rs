// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_vsock::VsockConnector;
use hyperlocal::{UnixConnector, Uri};
use log::debug;
use std::sync::OnceLock;

mod hyper_vsock;

#[cfg(feature = "prpc")]
pub mod prpc;

/// A response bound for callers whose peer is not trusted.
///
/// Not a default. Most users of this transport talk to something local or
/// operator-run and legitimately fetch as much as they asked for -- `dstack vmm
/// logs --lines 20000` is a megabyte on its own. But some talk to a CVM's guest
/// agent, which is exactly the party dstack's threat model does not trust, and
/// at least one of those polls on a timer against the whole fleet. Those callers
/// pass this. Compare `gateway/src/kv/https_client.rs`, which learned the same
/// lesson on the peer-facing sync client.
///
/// Far above anything a control-plane RPC returns, and far below anything that
/// matters.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Whether a request may travel over a connection an earlier one left open.
///
/// The default is to reuse. A control-plane call is strictly cheaper over a
/// warm connection, and a connection that died while idle costs one failed
/// request, which the caller was going to have to handle anyway.
///
/// A health probe is the exception, and the reason this is a decision a caller
/// states rather than a setting it inherits. Reuse there can report healthy
/// over a connection that real traffic would never be given: an agent out of
/// file descriptors, or with a full accept backlog, keeps serving whoever is
/// already connected while refusing everyone new. Every connection the gateway
/// proxies to an app is a new one, so "can a connection be opened and answered
/// right now" is the question the probe exists to ask -- and a pooled
/// connection is not asking it. Failing the other way is bounded by
/// comparison: a probe that trips over a dead pooled connection reports
/// unreachable, which needs `failure_threshold` of them in a row to become a
/// verdict, and the pool drops the connection on the way out.
///
/// This is not a new position for the project. `tappd`'s own watchdog probe
/// stopped reusing connections in fb0688b7f0 (#140) -- by moving
/// `reqwest::Client::new()` inside the loop, which is the same conclusion
/// reached without a way to say so. `Fresh` is that decision with a name, and
/// without the per-probe client construction it had to pay for it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectionReuse {
    /// Keep connections alive between requests to the same host.
    #[default]
    Pooled,
    /// Open a connection for this request and do not keep it.
    Fresh,
}

/// How to make a request, beyond where to send it.
///
/// A struct rather than two more positional arguments: this list has grown
/// once already and every entry is the kind that reads as an unlabelled `None`
/// or `true` at the call site. Construct with `..Default::default()` so a
/// field added later does not break callers.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestOptions {
    /// Refuse a response body larger than this. `None` accumulates whatever
    /// the peer sends; see [`MAX_RESPONSE_BYTES`].
    pub max_response_bytes: Option<usize>,
    /// See [`ConnectionReuse`].
    pub connection_reuse: ConnectionReuse,
}

/// The HTTP client every request over `base` shares, one per reuse policy.
///
/// Built once and kept. A `reqwest::Client` is a handle around a connection
/// pool, a DNS resolver and a TLS configuration; building one per request --
/// which this module did until now -- pays for all three every time and then
/// discards the pool before anything can use it. Sharing the handle is what
/// removes that cost; sharing *connections* is a separate decision, which is
/// why `Fresh` is a second client rather than a flag on a request.
fn tcp_client(reuse: ConnectionReuse) -> Result<&'static reqwest::Client> {
    static POOLED: OnceLock<std::result::Result<reqwest::Client, String>> = OnceLock::new();
    static FRESH: OnceLock<std::result::Result<reqwest::Client, String>> = OnceLock::new();
    let cell = match reuse {
        ConnectionReuse::Pooled => &POOLED,
        ConnectionReuse::Fresh => &FRESH,
    };
    cell.get_or_init(|| {
        let builder = match reuse {
            ConnectionReuse::Pooled => reqwest::Client::builder(),
            // Zero, not a short idle timeout: the pool never hands a
            // connection back, so every request dials. A timeout would leave a
            // window in which it still does.
            ConnectionReuse::Fresh => reqwest::Client::builder().pool_max_idle_per_host(0),
        };
        builder.build().map_err(|err| err.to_string())
    })
    .as_ref()
    .map_err(|err| anyhow!("failed to build the HTTP client: {err}"))
}

/// As [`tcp_client`], for the Unix-socket transport.
fn unix_client(reuse: ConnectionReuse) -> &'static Client<UnixConnector, Full<Bytes>> {
    static POOLED: OnceLock<Client<UnixConnector, Full<Bytes>>> = OnceLock::new();
    static FRESH: OnceLock<Client<UnixConnector, Full<Bytes>>> = OnceLock::new();
    match reuse {
        ConnectionReuse::Pooled => {
            POOLED.get_or_init(|| Client::builder(TokioExecutor::new()).build(UnixConnector))
        }
        ConnectionReuse::Fresh => FRESH.get_or_init(|| {
            Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build(UnixConnector)
        }),
    }
}

/// As [`tcp_client`], for the vsock transport.
fn vsock_client(reuse: ConnectionReuse) -> &'static Client<VsockConnector, Full<Bytes>> {
    static POOLED: OnceLock<Client<VsockConnector, Full<Bytes>>> = OnceLock::new();
    static FRESH: OnceLock<Client<VsockConnector, Full<Bytes>>> = OnceLock::new();
    match reuse {
        ConnectionReuse::Pooled => {
            POOLED.get_or_init(|| Client::builder(TokioExecutor::new()).build(VsockConnector))
        }
        ConnectionReuse::Fresh => FRESH.get_or_init(|| {
            Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build(VsockConnector)
        }),
    }
}

fn mk_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

/// Sends an HTTP request to the supervisor.
///
/// # Arguments
///
/// * `method` - The HTTP method to use.
/// * `uri` - The URI to send the request to. Supports Unix sockets: `unix:/path/to/socket` or HTTP: `http://host:port`.
/// * `body` - The body of the request.
pub async fn http_request(
    method: &str,
    base: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    http_request_with_headers(method, base, path, body, &[]).await
}

/// Same as [`http_request`], with extra request headers (e.g. `Authorization`).
pub async fn http_request_with_headers(
    method: &str,
    base: &str,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>)> {
    http_request_bounded(method, base, path, body, headers, None).await
}

/// Same as [`http_request_with_headers`], refusing a response larger than
/// `max_bytes`.
///
/// `None` accumulates whatever the peer sends, which is what a caller fetching
/// logs or a large listing wants. Callers whose peer is untrusted -- anything
/// talking to a CVM's guest agent -- should pass [`MAX_RESPONSE_BYTES`]; see the
/// note there.
pub async fn http_request_bounded(
    method: &str,
    base: &str,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
    max_bytes: Option<usize>,
) -> Result<(u16, Vec<u8>)> {
    http_request_with_options(
        method,
        base,
        path,
        body,
        headers,
        RequestOptions {
            max_response_bytes: max_bytes,
            ..Default::default()
        },
    )
    .await
}

/// Same as [`http_request_bounded`], also choosing whether the request may
/// reuse a connection. See [`ConnectionReuse`].
pub async fn http_request_with_options(
    method: &str,
    base: &str,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
    options: RequestOptions,
) -> Result<(u16, Vec<u8>)> {
    let RequestOptions {
        max_response_bytes: max_bytes,
        connection_reuse,
    } = options;
    debug!("Sending HTTP request to {base}, path={path}");
    let mut response = if let Some(uds) = base.strip_prefix("unix:") {
        let path = if path.starts_with("/") {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let client = unix_client(connection_reuse);
        let unix_uri: hyper::Uri = Uri::new(uds, &path).into();
        let mut builder = Request::builder().method(method).uri(unix_uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder.body(Full::new(Bytes::copy_from_slice(body)))?;
        client.request(req).await?
    } else if base.starts_with("vsock:") {
        let client = vsock_client(connection_reuse);
        let uri = mk_url(base, path).parse::<hyper::Uri>()?;
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder.body(Full::new(Bytes::copy_from_slice(body)))?;
        client.request(req).await?
    } else {
        let uri = mk_url(base, path);
        let client = tcp_client(connection_reuse)?;
        let method = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut request = client.request(method, uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if !body.is_empty() {
            request = request.body(body.to_vec());
        }
        let mut response = request.send().await?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        // Chunk by chunk rather than `text()`, so the bound is enforced while
        // the body is still arriving instead of after it has been buffered.
        while let Some(chunk) = response.chunk().await? {
            push_bounded(&mut body, &chunk, max_bytes)?;
        }
        return Ok((status, body));
    };
    debug!("Response: {:?}", response);
    let mut body = Vec::new();
    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;
        if let Some(segment) = frame.data_ref() {
            push_bounded(&mut body, segment.iter().as_slice(), max_bytes)?;
        }
    }
    Ok((response.status().as_u16(), body))
}

fn push_bounded(body: &mut Vec<u8>, segment: &[u8], max_bytes: Option<usize>) -> Result<()> {
    if let Some(max) = max_bytes {
        if body.len() + segment.len() > max {
            bail!("response body exceeds {max} bytes");
        }
    }
    body.extend_from_slice(segment);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_vsock_uri_parsing() -> Result<(), Box<dyn Error>> {
        let uri = "vsock://2:1234/path".parse::<hyper::Uri>()?;
        assert_eq!(uri.scheme_str(), Some("vsock"));
        assert_eq!(uri.host(), Some("2"));
        assert_eq!(uri.port_u16(), Some(1234));
        assert_eq!(uri.path(), "/path");
        Ok(())
    }

    #[tokio::test]
    async fn http_transport_honors_requested_method() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await?;
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            Ok::<_, std::io::Error>(request)
        });

        let (status, body) = http_request("GET", &format!("http://{addr}"), "/logs", b"").await?;
        assert_eq!(status, 200);
        assert_eq!(body, b"ok");
        let request = server.await??;
        assert!(
            request.starts_with("GET /logs HTTP/1.1"),
            "unexpected request: {request:?}"
        );
        Ok(())
    }

    /// Several callers of this transport talk to peers they do not control --
    /// a CVM's guest agent answering `Worker.Health` or `Info` -- and at least
    /// one of them does it on a timer against the whole fleet. An unbounded
    /// body there is an out-of-memory the peer gets to schedule.
    #[tokio::test]
    async fn an_oversized_response_body_is_refused() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let oversized = MAX_RESPONSE_BYTES + 1;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await?;
            socket
                .write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {oversized}\r\n\r\n").as_bytes(),
                )
                .await?;
            // Written in chunks so the bound is hit while the body is still
            // arriving, which is the case that matters.
            let chunk = vec![b'x'; 64 * 1024];
            let mut sent = 0;
            while sent < oversized {
                let take = chunk.len().min(oversized - sent);
                if socket.write_all(&chunk[..take]).await.is_err() {
                    break;
                }
                sent += take;
            }
            Ok::<_, std::io::Error>(())
        });

        let err = http_request_bounded(
            "GET",
            &format!("http://{addr}"),
            "/prpc",
            b"",
            &[],
            Some(MAX_RESPONSE_BYTES),
        )
        .await
        .expect_err("an oversized body must be refused");
        assert!(
            format!("{err:#}").contains("exceeds"),
            "unexpected error: {err:#}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_response_body_within_the_bound_still_arrives() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let size = 128 * 1024;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await?;
            socket
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").as_bytes())
                .await?;
            socket.write_all(&vec![b'x'; size]).await?;
            Ok::<_, std::io::Error>(())
        });

        let (status, body) = http_request_bounded(
            "GET",
            &format!("http://{addr}"),
            "/prpc",
            b"",
            &[],
            Some(MAX_RESPONSE_BYTES),
        )
        .await?;
        assert_eq!(status, 200);
        assert_eq!(body.len(), size);
        Ok(())
    }

    /// The default is unbounded on purpose: `dstack vmm logs --lines 20000` is
    /// a legitimate multi-megabyte fetch from a local daemon, and capping it
    /// would turn a working command into an error.
    #[tokio::test]
    async fn an_unbounded_caller_still_gets_a_large_body() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let size = MAX_RESPONSE_BYTES + 4096;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await?;
            socket
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").as_bytes())
                .await?;
            socket.write_all(&vec![b'x'; size]).await?;
            Ok::<_, std::io::Error>(())
        });

        let (status, body) = http_request("GET", &format!("http://{addr}"), "/logs", b"").await?;
        assert_eq!(status, 200);
        assert_eq!(body.len(), size);
        Ok(())
    }

    #[tokio::test]
    async fn http_transport_sends_extra_headers() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await?;
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            Ok::<_, std::io::Error>(request)
        });

        let (status, _body) = http_request_with_headers(
            "POST",
            &format!("http://{addr}"),
            "/prpc/Status",
            b"{}",
            &[("Authorization", "Bearer secret-token")],
        )
        .await?;
        assert_eq!(status, 200);
        let request = server.await??;
        assert!(
            request.contains("authorization: Bearer secret-token")
                || request.contains("Authorization: Bearer secret-token"),
            "request is missing the Authorization header: {request:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_transport_omits_headers_when_none() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await?;
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            Ok::<_, std::io::Error>(request)
        });

        let (status, _body) = http_request("GET", &format!("http://{addr}"), "/x", b"").await?;
        assert_eq!(status, 200);
        let request = server.await??;
        assert!(
            !request.to_lowercase().contains("authorization:"),
            "unexpected Authorization header: {request:?}"
        );
        Ok(())
    }

    /// A keep-alive server that counts connections and serves requests on each
    /// until the peer goes away. Returns its address and the counter.
    async fn counting_server() -> (std::net::SocketAddr, std::sync::Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connections = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut pending = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        // One response per request, so a pooled client can send
                        // a second request down the same connection.
                        while !pending.windows(4).any(|w| w == b"\r\n\r\n") {
                            match socket.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => pending.extend_from_slice(&buf[..n]),
                            }
                        }
                        pending.clear();
                        if socket
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        (addr, connections)
    }

    async fn get_thrice(addr: std::net::SocketAddr, connection_reuse: ConnectionReuse) {
        for _ in 0..3 {
            let (status, _) = http_request_with_options(
                "GET",
                &format!("http://{addr}"),
                "/x",
                b"",
                &[],
                RequestOptions {
                    connection_reuse,
                    ..Default::default()
                },
            )
            .await
            .expect("request should succeed");
            assert_eq!(status, 200);
        }
    }

    /// The half of the shared-client change that is a behaviour, not a saving.
    ///
    /// `Fresh` exists so a health probe keeps testing what it used to test back
    /// when every request built its own client: that a connection can be opened
    /// *now*. Nothing in the type system enforces that
    /// `pool_max_idle_per_host(0)` means what the doc comment claims, so this
    /// counts connections at the socket.
    #[tokio::test]
    async fn fresh_dials_every_request_and_pooled_does_not() {
        let (addr, connections) = counting_server().await;
        get_thrice(addr, ConnectionReuse::Fresh).await;
        assert_eq!(
            connections.load(Ordering::SeqCst),
            3,
            "a probe must open its own connection, or it cannot see an agent \
             that has stopped accepting them"
        );

        let (addr, connections) = counting_server().await;
        get_thrice(addr, ConnectionReuse::Pooled).await;
        assert_eq!(
            connections.load(Ordering::SeqCst),
            1,
            "the default should be reusing the connection it already has"
        );
    }
}
