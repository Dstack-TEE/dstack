// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Context as _, Result};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::tokio::TokioIo;
use proxy_protocol::ProxyHeader;
use rustls::version::{TLS12, TLS13};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};
use tracing::debug;

use crate::cert_store::CertResolver;

use crate::config::{CryptoProvider, ProxyConfig, TlsVersion};
use crate::main_service::Proxy;

use super::io_bridge::bridge;
use super::port_policy::{filter_allowed_addresses, should_send_pp};
use super::tls_passthough::connect_multiple_hosts;

#[pin_project::pin_project]
struct IgnoreUnexpectedEofStream<S> {
    #[pin]
    stream: S,
}

impl<S> IgnoreUnexpectedEofStream<S> {
    fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> AsyncRead for IgnoreUnexpectedEofStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project().stream.poll_read(cx, buf) {
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Poll::Ready(Ok(())),
            output => output,
        }
    }
}

impl<S> AsyncWrite for IgnoreUnexpectedEofStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<std::result::Result<usize, io::Error>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

/// Create a TLS acceptor using CertResolver for SNI-based certificate resolution
///
/// The CertResolver allows atomic certificate updates without recreating the acceptor.
pub(crate) fn create_acceptor_with_cert_resolver(
    proxy_config: &ProxyConfig,
    cert_resolver: Arc<CertResolver>,
    h2: bool,
) -> Result<TlsAcceptor> {
    let provider = match proxy_config.tls_crypto_provider {
        CryptoProvider::AwsLcRs => rustls::crypto::aws_lc_rs::default_provider(),
        CryptoProvider::Ring => rustls::crypto::ring::default_provider(),
    };
    // Stateless session tickets. TLS 1.2 resumption already works via the
    // in-memory session-ID cache, but TLS 1.3 resumption requires a ticketer;
    // without one, every reconnect pays a full handshake (a large RSA signing
    // cost on the server). Installing a ticketer restores resumption for 1.3.
    let ticketer = match proxy_config.tls_crypto_provider {
        CryptoProvider::AwsLcRs => rustls::crypto::aws_lc_rs::Ticketer::new(),
        CryptoProvider::Ring => rustls::crypto::ring::Ticketer::new(),
    }
    .context("failed to create TLS session ticketer")?;
    let supported_versions = proxy_config
        .tls_versions
        .iter()
        .map(|v| match v {
            TlsVersion::Tls12 => &TLS12,
            TlsVersion::Tls13 => &TLS13,
        })
        .collect::<Vec<_>>();

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&supported_versions)
        .context("failed to build TLS config")?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    config.ticketer = ticketer;

    // kTLS needs the negotiated traffic secrets so it can install them into
    // the kernel's TLS ULP. This is opt-in because it moves session keys
    // outside rustls' control (see the `ktls` config docs).
    if proxy_config.ktls.is_some() {
        config.enable_secret_extraction = true;
    }

    if h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }

    let acceptor = TlsAcceptor::from(Arc::new(config));

    Ok(acceptor)
}

fn json_response(body: &impl Serialize) -> Result<Response<String>> {
    let body = serde_json::to_string(body).context("Failed to serialize response")?;
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .context("Failed to build response")
}

fn empty_response(status: StatusCode) -> Result<Response<String>> {
    Response::builder()
        .status(status)
        .body(String::new())
        .context("Failed to build response")
}

impl Proxy {
    pub(crate) async fn handle_this_node(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
        port: u16,
        h2: bool,
    ) -> Result<()> {
        if port != 80 {
            bail!("Only port 80 is supported for this node");
        }
        let stream = self.tls_accept(inbound, buffer, h2).await?;
        let io = TokioIo::new(stream);

        let service = service_fn(|req: Request<Incoming>| async move {
            // Only respond to GET / requests
            if req.method() != hyper::Method::GET {
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
            if req.uri().path() == "/health" {
                return empty_response(StatusCode::OK);
            }
            let path = req.uri().path().trim_start_matches("/.dstack");
            match path {
                "/index" => {
                    let body = serde_json::json!({
                        "type": "dstack gateway",
                        "paths": [
                            "/index",
                            "/app-info",
                            "/acme-info",
                        ],
                    });
                    json_response(&body)
                }
                "/app-info" => {
                    let agent = crate::dstack_agent().context("Failed to get dstack agent")?;
                    let app_info = agent.info().await.context("Failed to get app info")?;
                    json_response(&app_info)
                }
                "/acme-info" => {
                    let acme_info = self.acme_info(None).context("Failed to get acme info")?;
                    json_response(&acme_info)
                }
                _ => empty_response(StatusCode::NOT_FOUND),
            }
        });

        http1::Builder::new()
            .serve_connection(io, service)
            .await
            .context("Failed to serve HTTP connection")?;

        Ok(())
    }

    /// Deprecated legacy endpoint
    pub(crate) async fn handle_health_check(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
        port: u16,
        h2: bool,
    ) -> Result<()> {
        if port != 80 {
            bail!("Only port 80 is supported for health checks");
        }
        let stream = self.tls_accept(inbound, buffer, h2).await?;

        // Wrap the TLS stream with TokioIo to make it compatible with hyper 1.x
        let io = TokioIo::new(stream);

        let service = service_fn(|req: Request<Incoming>| async move {
            // Only respond to GET / requests
            if req.method() != hyper::Method::GET || req.uri().path() != "/" {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(String::new())
                    .context("Failed to build response");
            }
            Response::builder()
                .status(StatusCode::OK)
                .body(String::new())
                .context("Failed to build response")
        });

        http1::Builder::new()
            .serve_connection(io, service)
            .await
            .context("Failed to serve HTTP connection")?;

        Ok(())
    }

    async fn tls_accept(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
        h2: bool,
    ) -> Result<TlsStream<MergedStream>> {
        let stream = MergedStream {
            buffer,
            buffer_cursor: 0,
            inbound,
        };
        let acceptor = if h2 {
            &self.h2_acceptor
        } else {
            &self.acceptor
        };
        let tls_stream = timeout(
            self.config.proxy.timeouts.handshake,
            acceptor.accept(stream),
        )
        .await
        .context("handshake timeout")?
        .context("failed to accept tls connection")?;
        Ok(tls_stream)
    }

    /// Accept a TLS connection keeping the `CorkStream` wrapper, so the
    /// connection can be handed to the kernel later without re-wrapping.
    async fn tls_accept_corked(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
        h2: bool,
    ) -> Result<TlsStream<ktls::CorkStream<MergedStream>>> {
        let stream = ktls::CorkStream::new(MergedStream {
            buffer,
            buffer_cursor: 0,
            inbound,
        });
        let acceptor = if h2 {
            &self.h2_acceptor
        } else {
            &self.acceptor
        };
        timeout(
            self.config.proxy.timeouts.handshake,
            acceptor.accept(stream),
        )
        .await
        .context("handshake timeout")?
        .context("failed to accept tls connection")
    }

    /// Accept a TLS connection and hand the socket over to kernel TLS.
    ///
    /// The handshake still runs in rustls; afterwards the negotiated keys are
    /// installed into the kernel TLS ULP so record encryption happens there.
    /// The inner IO must be wrapped in `CorkStream` because that is the only
    /// way to drain a rustls stream cleanly at a record boundary.
    async fn tls_accept_ktls(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
        h2: bool,
    ) -> Result<ktls::KtlsStream<MergedStream>> {
        let stream = ktls::CorkStream::new(MergedStream {
            buffer,
            buffer_cursor: 0,
            inbound,
        });
        let acceptor = if h2 {
            &self.h2_acceptor
        } else {
            &self.acceptor
        };
        let tls_stream = timeout(
            self.config.proxy.timeouts.handshake,
            acceptor.accept(stream),
        )
        .await
        .context("handshake timeout")?
        .context("failed to accept tls connection")?;
        super::stats::record_ktls_offload(ktls::config_ktls_server(tls_stream).await)
            .context("failed to enable kernel TLS")
    }

    pub(super) async fn proxy(
        &self,
        inbound: TcpStream,
        pp_header: ProxyHeader,
        buffer: Vec<u8>,
        app_id: &str,
        port: u16,
        h2: bool,
    ) -> Result<()> {
        if app_id == "health" {
            return self.handle_health_check(inbound, buffer, port, h2).await;
        }
        if app_id == "gateway" {
            return self.handle_this_node(inbound, buffer, port, h2).await;
        }
        let addresses = self
            .lock()
            .select_top_n_hosts(app_id)
            .with_context(|| format!("app <{app_id}> not found"))?;
        let addresses = filter_allowed_addresses(self, addresses, app_id, port)?;
        debug!("selected top n hosts: {addresses:?}");
        if let Some(ktls) = &self.config.proxy.ktls {
            let splice = self.config.proxy.tcp_splice.as_ref();
            // A gated offload only pays off if the socket is spliced afterwards,
            // so it needs both sections configured.
            if let Some(splice) = splice.filter(|_| !ktls.is_immediate()) {
                // Adaptive: stay in userspace rustls until the connection proves
                // itself worth the offload, then hand it to the kernel.
                let tls_stream = self.tls_accept_corked(inbound, buffer, h2).await?;
                let (mut outbound, _counter, instance_id) =
                    self.connect_upstream(addresses, port, app_id).await?;
                self.send_pp_header(&mut outbound, &instance_id, port, pp_header)
                    .await?;
                return super::adaptive_ktls::relay_with_adaptive_offload(
                    tls_stream,
                    outbound,
                    ktls,
                    splice,
                    self.config.proxy.idle_timeout(),
                )
                .await;
            }
            let tls_stream = self.tls_accept_ktls(inbound, buffer, h2).await?;
            if let Some(splice) = splice {
                // With kTLS the socket carries plaintext from userspace's point
                // of view, so the payload can be relayed with splice and never
                // enters this process at all.
                let (mut outbound, _counter, instance_id) =
                    self.connect_upstream(addresses, port, app_id).await?;
                self.send_pp_header(&mut outbound, &instance_id, port, pp_header)
                    .await?;
                let (drained, stream) = tls_stream.into_raw();
                let (buffered, tcp) = stream.into_parts();
                // These two are not the same kind of data and must not be
                // treated as interchangeable: `drained` is plaintext rustls
                // decrypted past the handshake and owes to the app, while
                // `buffered` is whatever raw *ciphertext* was left in the SNI
                // sniff buffer. Forwarding the latter would hand the app TLS
                // records to interpret as application data.
                //
                // A completed handshake always consumes the sniff buffer, so
                // this is unreachable rather than merely unlikely -- but it is
                // cheap to refuse instead of finding out by corrupting a stream.
                if !buffered.is_empty() {
                    bail!(
                        "{} bytes of unconsumed ciphertext at kTLS handover",
                        buffered.len()
                    );
                }
                // Plaintext rustls already decrypted has to reach the app before
                // the kernel starts moving bytes directly.
                let drained = drained.unwrap_or_default();
                if !drained.is_empty() {
                    outbound
                        .write_all(&drained)
                        .await
                        .context("failed to flush drained data to app")?;
                }
                // `tcp` is now a kernel-TLS socket, so closing it needs a
                // close_notify and not just a FIN.
                return super::splice::splice_bidirectional(
                    tcp,
                    outbound,
                    splice.release_idle_pipes,
                    self.config.proxy.idle_timeout(),
                    super::splice::CloseKind::KernelTls,
                )
                .await
                .context("ktls splice error");
            }
            self.relay_to_app(tls_stream, addresses, port, app_id, pp_header)
                .await
        } else {
            let tls_stream = self.tls_accept(inbound, buffer, h2).await?;
            self.relay_to_app(tls_stream, addresses, port, app_id, pp_header)
                .await
        }
    }

    /// Connect to the app and relay an already-terminated TLS stream to it.
    ///
    /// Generic over the accepted stream so the userspace-rustls and kTLS
    /// paths share the same connect / PROXY-protocol / bridging logic.
    /// Race a connection to the app's top-N addresses.
    async fn connect_upstream(
        &self,
        addresses: super::AddressGroup,
        port: u16,
        app_id: &str,
    ) -> Result<(TcpStream, crate::models::EnteredCounter, String)> {
        let max_connections = self.config.proxy.max_connections_per_app;
        timeout(
            self.config.proxy.timeouts.connect,
            connect_multiple_hosts(addresses, port, max_connections, app_id),
        )
        .await
        .map_err(|_| anyhow!("connecting timeout"))?
        .context("failed to connect to app")
    }

    /// Forward the client's address to the app when its port policy asks for it.
    async fn send_pp_header(
        &self,
        outbound: &mut TcpStream,
        instance_id: &str,
        port: u16,
        pp_header: ProxyHeader,
    ) -> Result<()> {
        if should_send_pp(self, instance_id, port) {
            let pp_header_bin =
                proxy_protocol::encode(pp_header).context("failed to encode pp header")?;
            outbound.write_all(&pp_header_bin).await?;
        }
        Ok(())
    }

    async fn relay_to_app<S>(
        &self,
        tls_stream: S,
        addresses: super::AddressGroup,
        port: u16,
        app_id: &str,
        pp_header: ProxyHeader,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut outbound, _counter, instance_id) =
            self.connect_upstream(addresses, port, app_id).await?;
        self.send_pp_header(&mut outbound, &instance_id, port, pp_header)
            .await?;
        bridge(
            IgnoreUnexpectedEofStream::new(tls_stream),
            outbound,
            &self.config.proxy,
        )
        .await
        .context("bridge error")?;
        Ok(())
    }
}

/// Give up the raw socket *and* anything still buffered in front of it.
///
/// Deliberately not `Into<TcpStream>`: that conversion existed, and it dropped
/// the remainder silently. Whatever is left here is raw ciphertext from the SNI
/// sniff, which cannot be forwarded to an app expecting plaintext and cannot be
/// pushed back once the socket belongs to the kernel -- so the only safe thing
/// is to make every caller look at it.
pub(crate) trait SocketParts {
    fn into_socket_parts(self) -> (Vec<u8>, TcpStream);
}

#[pin_project::pin_project]
struct MergedStream {
    buffer: Vec<u8>,
    buffer_cursor: usize,
    #[pin]
    inbound: TcpStream,
}

impl AsyncRead for MergedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let mut cursor = *this.buffer_cursor;
        if cursor < this.buffer.len() {
            let n = std::cmp::min(buf.remaining(), this.buffer.len() - cursor);
            buf.put_slice(&this.buffer[cursor..cursor + n]);
            cursor += n;
            if cursor == this.buffer.len() {
                cursor = 0;
                *this.buffer = vec![];
            }
            *this.buffer_cursor = cursor;
            return Poll::Ready(Ok(()));
        }
        this.inbound.poll_read(cx, buf)
    }
}
impl MergedStream {
    /// Unwrap to the raw socket, returning any bytes still buffered from the
    /// pre-handshake sniff. After a completed handshake the buffer is drained,
    /// so the returned `Vec` is normally empty; callers that bypass the
    /// `AsyncRead` impl (e.g. splice) must still handle a non-empty remainder.
    fn into_parts(self) -> (Vec<u8>, TcpStream) {
        let remaining = self.buffer[self.buffer_cursor.min(self.buffer.len())..].to_vec();
        (remaining, self.inbound)
    }
}

impl SocketParts for MergedStream {
    fn into_socket_parts(self) -> (Vec<u8>, TcpStream) {
        self.into_parts()
    }
}

impl std::os::fd::AsRawFd for MergedStream {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inbound.as_raw_fd()
    }
}

impl ktls::AsyncReadReady for MergedStream {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Safe to defer to the socket: by the time kTLS takes over, the
        // buffered ClientHello prefix has already been consumed by rustls.
        self.inbound.poll_read_ready(cx)
    }
}

impl AsyncWrite for MergedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        self.project().inbound.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        self.project().inbound.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        self.project().inbound.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        self.project().inbound.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inbound.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;

    async fn merged_with(buffer: Vec<u8>) -> MergedStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).await.expect("connect");
        drop(client);
        let (inbound, _) = listener.accept().await.expect("accept");
        MergedStream {
            buffer,
            buffer_cursor: 0,
            inbound,
        }
    }

    /// The kTLS handover reads the remainder through this, and forwarding raw
    /// ciphertext to an app expecting plaintext is the failure it guards
    /// against -- so an unconsumed sniff buffer has to be visible, not silently
    /// swallowed by the unwrap.
    #[tokio::test]
    async fn an_unconsumed_sniff_buffer_is_surfaced_not_dropped() {
        let stream = merged_with(b"leftover ciphertext".to_vec()).await;
        let (remainder, _socket) = stream.into_socket_parts();
        assert_eq!(remainder, b"leftover ciphertext");
    }

    /// The normal case: rustls drains the sniff buffer during the handshake, so
    /// the handover sees nothing left and proceeds.
    #[tokio::test]
    async fn a_consumed_sniff_buffer_leaves_no_remainder() {
        let mut stream = merged_with(b"clienthello".to_vec()).await;
        let mut sink = vec![0u8; 11];
        stream.read_exact(&mut sink).await.expect("read");
        assert_eq!(&sink, b"clienthello");
        let (remainder, _socket) = stream.into_socket_parts();
        assert!(remainder.is_empty(), "got {remainder:?}");
    }
}

#[cfg(test)]
mod local_response_tests {
    use super::{empty_response, json_response, IgnoreUnexpectedEofStream};
    use hyper::StatusCode;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

    struct ErrorReader(io::ErrorKind);

    impl AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(self.0)))
        }
    }

    #[tokio::test]
    async fn gateway_internal_batch_005_local_response_and_stream_matrix() {
        let json = json_response(&serde_json::json!({
            "type": "dstack gateway",
            "paths": ["/index", "/app-info", "/acme-info"],
        }))
        .expect("bounded JSON response must build");
        assert_eq!(json.status(), StatusCode::OK);
        assert_eq!(
            json.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let parsed: serde_json::Value =
            serde_json::from_str(json.body()).expect("response body must be exact JSON");
        assert_eq!(parsed["type"], "dstack gateway");
        assert_eq!(parsed["paths"].as_array().map(Vec::len), Some(3));

        for status in [
            StatusCode::OK,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
        ] {
            let response = empty_response(status).expect("empty response must build");
            assert_eq!(response.status(), status);
            assert!(response.body().is_empty());
        }

        let mut expected_eof =
            IgnoreUnexpectedEofStream::new(ErrorReader(io::ErrorKind::UnexpectedEof));
        let mut byte = [0_u8; 1];
        assert_eq!(expected_eof.read(&mut byte).await.unwrap(), 0);

        let mut unexpected_error =
            IgnoreUnexpectedEofStream::new(ErrorReader(io::ErrorKind::ConnectionReset));
        let error = unexpected_error
            .read(&mut byte)
            .await
            .expect_err("non-EOF transport errors must stay visible");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }
}
