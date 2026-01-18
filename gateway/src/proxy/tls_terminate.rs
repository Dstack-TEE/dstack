// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Context as _, Result};
use fs_err as fs;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::tokio::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version::{TLS12, TLS13};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};
use tracing::{debug, info};

use crate::cert_store::CertStore;
use crate::config::{CryptoProvider, ProxyConfig, TlsVersion};
use crate::main_service::Proxy;

use super::io_bridge::bridge;
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

/// Create a TLS acceptor from certificate files (legacy single-cert mode)
pub(crate) fn create_acceptor(config: &ProxyConfig, h2: bool) -> Result<TlsAcceptor> {
    let cert_pem = fs::read(&config.cert_chain).context("failed to read certificate")?;
    let key_pem = fs::read(&config.cert_key).context("failed to read private key")?;
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate")?;
    let key =
        PrivateKeyDer::from_pem_slice(key_pem.as_slice()).context("failed to parse private key")?;

    let provider = match config.tls_crypto_provider {
        CryptoProvider::AwsLcRs => rustls::crypto::aws_lc_rs::default_provider(),
        CryptoProvider::Ring => rustls::crypto::ring::default_provider(),
    };
    let supported_versions = config
        .tls_versions
        .iter()
        .map(|v| match v {
            TlsVersion::Tls12 => &TLS12,
            TlsVersion::Tls13 => &TLS13,
        })
        .collect::<Vec<_>>();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&supported_versions)
        .context("Failed to build TLS config")?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    if h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }

    let acceptor = TlsAcceptor::from(Arc::new(config));

    Ok(acceptor)
}

/// Create a TLS acceptor using CertStore for SNI-based certificate resolution
pub(crate) fn create_acceptor_with_cert_store(
    proxy_config: &ProxyConfig,
    cert_store: Arc<CertStore>,
    h2: bool,
) -> Result<TlsAcceptor> {
    let provider = match proxy_config.tls_crypto_provider {
        CryptoProvider::AwsLcRs => rustls::crypto::aws_lc_rs::default_provider(),
        CryptoProvider::Ring => rustls::crypto::ring::default_provider(),
    };
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
        .with_cert_resolver(cert_store);

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
    /// Reload the TLS acceptor with fresh certificates
    pub fn reload_certificates(&self) -> Result<()> {
        info!("Reloading TLS certificates");
        // Replace the acceptor with the new one
        if let Ok(mut acceptor) = self.acceptor.write() {
            *acceptor = create_acceptor(&self.config.proxy, false)?;
            info!("TLS certificates successfully reloaded");
        } else {
            bail!("Failed to acquire write lock for TLS acceptor");
        }

        if let Ok(mut acceptor) = self.h2_acceptor.write() {
            *acceptor = create_acceptor(&self.config.proxy, true)?;
            info!("TLS certificates successfully reloaded");
        } else {
            bail!("Failed to acquire write lock for TLS acceptor");
        }

        Ok(())
    }

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

    /// Handle TLS connections for domains with managed certificates (e.g., wildcard certs)
    /// This serves a health endpoint for any SNI that matches a certificate in CertStore
    pub(crate) async fn handle_managed_cert_domain(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
    ) -> Result<()> {
        let stream = self.tls_accept(inbound, buffer, false).await?;
        let io = TokioIo::new(stream);

        let service = service_fn(|req: Request<Incoming>| async move {
            if req.method() != hyper::Method::GET {
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
            match req.uri().path() {
                "/" | "/health" => empty_response(StatusCode::OK),
                _ => empty_response(StatusCode::NOT_FOUND),
            }
        });

        http1::Builder::new()
            .serve_connection(io, service)
            .await
            .context("failed to serve managed cert domain HTTP connection")?;

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
            self.h2_acceptor
                .read()
                .expect("Failed to acquire read lock for TLS acceptor")
                .clone()
        } else {
            self.acceptor
                .read()
                .expect("Failed to acquire read lock for TLS acceptor")
                .clone()
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

    pub(crate) async fn proxy(
        &self,
        inbound: TcpStream,
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
            .with_context(|| format!("app {app_id} not found"))?;
        debug!("selected top n hosts: {addresses:?}");
        let tls_stream = self.tls_accept(inbound, buffer, h2).await?;
        let (outbound, _counter) = timeout(
            self.config.proxy.timeouts.connect,
            connect_multiple_hosts(addresses, port),
        )
        .await
        .map_err(|_| anyhow!("connecting timeout"))?
        .context("failed to connect to app")?;
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
