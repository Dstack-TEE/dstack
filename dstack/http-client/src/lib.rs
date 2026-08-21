// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_vsock::VsockClientExt;
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use log::debug;

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
    debug!("Sending HTTP request to {base}, path={path}");
    let mut response = if let Some(uds) = base.strip_prefix("unix:") {
        let path = if path.starts_with("/") {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
        let unix_uri: hyper::Uri = Uri::new(uds, &path).into();
        let mut builder = Request::builder().method(method).uri(unix_uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder.body(Full::new(Bytes::copy_from_slice(body)))?;
        client.request(req).await?
    } else if base.starts_with("vsock:") {
        let client = Client::vsock();
        let uri = mk_url(base, path).parse::<hyper::Uri>()?;
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder.body(Full::new(Bytes::copy_from_slice(body)))?;
        client.request(req).await?
    } else {
        let uri = mk_url(base, path);
        let client = reqwest::Client::builder().build()?;
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
}
