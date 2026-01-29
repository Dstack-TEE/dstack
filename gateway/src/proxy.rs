// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::{bail, Context, Result};
use sni::extract_sni;
pub(crate) use tls_terminate::create_acceptor;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{debug, error, info, info_span, Instrument};

use crate::{config::ProxyConfig, main_service::Proxy, models::EnteredCounter};

/// Abstraction over inbound connection types (TCP or QUIC stream).
#[pin_project::pin_project(project = InboundStreamProj)]
pub(crate) enum InboundStream {
    Tcp(#[pin] TcpStream),
    Quic(#[pin] QuicBiStream),
}

/// Wrapper that combines quinn SendStream + RecvStream into a single AsyncRead + AsyncWrite.
#[pin_project::pin_project]
pub(crate) struct QuicBiStream {
    #[pin]
    send: quinn::SendStream,
    #[pin]
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self.project().recv, cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self.project().send, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self.project().send, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self.project().send, cx)
    }
}

impl AsyncRead for InboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project() {
            InboundStreamProj::Tcp(s) => s.poll_read(cx, buf),
            InboundStreamProj::Quic(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for InboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            InboundStreamProj::Tcp(s) => s.poll_write(cx, buf),
            InboundStreamProj::Quic(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            InboundStreamProj::Tcp(s) => s.poll_flush(cx),
            InboundStreamProj::Quic(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            InboundStreamProj::Tcp(s) => s.poll_shutdown(cx),
            InboundStreamProj::Quic(s) => s.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            InboundStreamProj::Tcp(s) => s.poll_write_vectored(cx, bufs),
            InboundStreamProj::Quic(s) => s.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            InboundStream::Tcp(s) => s.is_write_vectored(),
            InboundStream::Quic(_) => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AddressInfo {
    pub ip: Ipv4Addr,
    pub counter: Arc<AtomicU64>,
}

pub(crate) type AddressGroup = smallvec::SmallVec<[AddressInfo; 4]>;

mod io_bridge;
mod sni;
mod tls_passthough;
mod tls_terminate;

async fn take_sni(stream: &mut (impl AsyncRead + Unpin)) -> Result<(Option<String>, Vec<u8>)> {
    let mut buffer = vec![0u8; 4096];
    let mut data_len = 0;
    loop {
        // read data from stream
        let n = stream
            .read(&mut buffer[data_len..])
            .await
            .context("failed to read from incoming tcp stream")?;
        if n == 0 {
            break;
        }
        data_len += n;

        if let Some(sni) = extract_sni(&buffer[..data_len]) {
            let sni = String::from_utf8(sni.to_vec()).context("sni: invalid utf-8")?;
            debug!("got sni: {sni}");
            buffer.truncate(data_len);
            return Ok((Some(sni), buffer));
        }
    }
    buffer.truncate(data_len);
    Ok((None, buffer))
}

fn is_subdomain(sni: &str, base_domain: &str) -> bool {
    sni.ends_with(base_domain)
}

#[derive(Debug)]
struct DstInfo {
    app_id: String,
    port: u16,
    is_tls: bool,
    is_h2: bool,
}

fn parse_destination(sni: &str, dotted_base_domain: &str) -> Result<DstInfo> {
    // format: <app_id>[-<port>][s].<base_domain>
    let subdomain = sni
        .strip_suffix(dotted_base_domain)
        .context("invalid sni format")?;
    if subdomain.contains('.') {
        bail!("only one level of subdomain is supported, got sni={sni}, subdomain={subdomain}");
    }
    let mut parts = subdomain.split('-');
    let app_id = parts.next().context("no app id found")?.to_owned();
    if app_id.is_empty() {
        bail!("app id is empty");
    }
    let last_part = parts.next();
    let is_tls;
    let port;
    let is_h2;
    match last_part {
        None => {
            is_tls = false;
            is_h2 = false;
            port = None;
        }
        Some(last_part) => {
            let (port_str, has_g) = match last_part.strip_suffix('g') {
                Some(without_g) => (without_g, true),
                None => (last_part, false),
            };

            let (port_str, has_s) = match port_str.strip_suffix('s') {
                Some(without_s) => (without_s, true),
                None => (port_str, false),
            };
            if has_g && has_s {
                bail!("invalid sni format: `gs` is not allowed");
            }
            is_h2 = has_g;
            is_tls = has_s;
            port = if port_str.is_empty() {
                None
            } else {
                Some(port_str.parse::<u16>().context("invalid port")?)
            };
        }
    };
    let port = port.unwrap_or(if is_tls { 443 } else { 80 });
    if parts.next().is_some() {
        bail!("invalid sni format");
    }
    Ok(DstInfo {
        app_id,
        port,
        is_tls,
        is_h2,
    })
}

pub static NUM_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

async fn handle_connection(
    mut inbound: InboundStream,
    state: Proxy,
    dotted_base_domain: &str,
) -> Result<()> {
    let timeouts = &state.config.proxy.timeouts;
    let (sni, buffer) = timeout(timeouts.handshake, take_sni(&mut inbound))
        .await
        .context("take sni timeout")?
        .context("failed to take sni")?;
    let Some(sni) = sni else {
        bail!("no sni found");
    };
    if is_subdomain(&sni, dotted_base_domain) {
        let dst = parse_destination(&sni, dotted_base_domain)?;
        debug!("dst: {dst:?}");
        if dst.is_tls {
            tls_passthough::proxy_to_app(state, inbound, buffer, &dst.app_id, dst.port).await
        } else {
            state
                .proxy(inbound, buffer, &dst.app_id, dst.port, dst.is_h2)
                .await
        }
    } else {
        tls_passthough::proxy_with_sni(state, inbound, buffer, &sni).await
    }
}

fn generate_self_signed_cert() -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("failed to generate self-signed cert")?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    );
    let cert = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    Ok((cert, key))
}

#[inline(never)]
pub async fn proxy_main(config: &ProxyConfig, proxy: Proxy) -> Result<()> {
    let workers_rt = tokio::runtime::Builder::new_multi_thread()
        .thread_name("proxy-worker")
        .enable_all()
        .worker_threads(config.workers)
        .build()
        .context("Failed to build Tokio runtime")?;

    let dotted_base_domain = {
        let base_domain = config.base_domain.as_str();
        let base_domain = base_domain.strip_prefix(".").unwrap_or(base_domain);
        Arc::new(format!(".{base_domain}"))
    };
    let tcp_listener = TcpListener::bind((config.listen_addr, config.listen_port))
        .await
        .with_context(|| {
            format!(
                "failed to bind {}:{}",
                config.listen_addr, config.listen_port
            )
        })?;
    info!(
        "tcp bridge listening on {}:{}",
        config.listen_addr, config.listen_port
    );

    let quic_endpoint = if let Some(quic_port) = config.quic_listen_port {
        let (cert, key) = generate_self_signed_cert()?;
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .context("failed to build rustls server config")?;
        server_crypto.alpn_protocols = vec![b"dstack".to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .context("failed to build quic server config")?,
        ));

        let endpoint = quinn::Endpoint::server(
            server_config,
            format!("0.0.0.0:{quic_port}").parse()?,
        )
        .context("failed to bind QUIC endpoint")?;
        info!("QUIC bridge listening on UDP port {quic_port}");
        Some(endpoint)
    } else {
        None
    };

    loop {
        if let Some(ref quic_endpoint) = quic_endpoint {
            tokio::select! {
                result = tcp_listener.accept() => {
                    match result {
                        Ok((stream, from)) => {
                            spawn_connection(
                                &workers_rt,
                                InboundStream::Tcp(stream),
                                from.to_string(),
                                proxy.clone(),
                                dotted_base_domain.clone(),
                            );
                        }
                        Err(e) => error!("failed to accept tcp connection: {e:?}"),
                    }
                }
                incoming = quic_endpoint.accept() => {
                    if let Some(incoming) = incoming {
                        let proxy = proxy.clone();
                        let dotted_base_domain = dotted_base_domain.clone();
                        let handle = workers_rt.handle().clone();
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(conn) => {
                                    let from = format!("quic:{}", conn.remote_address());
                                    info!(%from, "new QUIC connection");
                                    handle_quic_connection(
                                        conn, &handle, proxy, dotted_base_domain,
                                    ).await;
                                }
                                Err(e) => error!("failed to accept QUIC connection: {e:?}"),
                            }
                        });
                    }
                }
            }
        } else {
            match tcp_listener.accept().await {
                Ok((stream, from)) => {
                    spawn_connection(
                        &workers_rt,
                        InboundStream::Tcp(stream),
                        from.to_string(),
                        proxy.clone(),
                        dotted_base_domain.clone(),
                    );
                }
                Err(e) => error!("failed to accept tcp connection: {e:?}"),
            }
        };
    }
}

/// Spawn a single inbound connection handler on the worker runtime.
fn spawn_connection(
    workers_rt: &tokio::runtime::Runtime,
    inbound: InboundStream,
    from: String,
    proxy: Proxy,
    dotted_base_domain: Arc<String>,
) {
    let span = info_span!("conn", id = next_connection_id());
    let _enter = span.enter();
    let conn_entered = EnteredCounter::new(&NUM_CONNECTIONS);

    info!(%from, "new connection");
    workers_rt.spawn(
        async move {
            let _conn_entered = conn_entered;
            let timeouts = &proxy.config.proxy.timeouts;
            let result = timeout(
                timeouts.total,
                handle_connection(inbound, proxy, &dotted_base_domain),
            )
            .await;
            match result {
                Ok(Ok(_)) => {
                    info!("connection closed");
                }
                Ok(Err(e)) => {
                    error!("connection error: {e:?}");
                }
                Err(_) => {
                    error!("connection kept too long, force closing");
                }
            }
        }
        .in_current_span(),
    );
}

/// Handle a QUIC connection.
/// Each accepted bidirectional stream becomes an independent inbound connection.
async fn handle_quic_connection(
    conn: quinn::Connection,
    workers_handle: &tokio::runtime::Handle,
    proxy: Proxy,
    dotted_base_domain: Arc<String>,
) {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let inbound = InboundStream::Quic(QuicBiStream::new(send, recv));
                let span = info_span!("conn", id = next_connection_id());
                let _enter = span.enter();
                let conn_entered = EnteredCounter::new(&NUM_CONNECTIONS);

                debug!("new QUIC stream");
                let proxy = proxy.clone();
                let dotted_base_domain = dotted_base_domain.clone();
                workers_handle.spawn(
                    async move {
                        let _conn_entered = conn_entered;
                        let timeouts = &proxy.config.proxy.timeouts;
                        let result = timeout(
                            timeouts.total,
                            handle_connection(inbound, proxy, &dotted_base_domain),
                        )
                        .await;
                        match result {
                            Ok(Ok(_)) => {
                                info!("connection closed");
                            }
                            Ok(Err(e)) => {
                                error!("connection error: {e:?}");
                            }
                            Err(_) => {
                                error!("connection kept too long, force closing");
                            }
                        }
                    }
                    .in_current_span(),
                );
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                info!("QUIC connection closed by peer");
                break;
            }
            Err(e) => {
                error!("QUIC accept_bi error: {e}");
                break;
            }
        }
    }
}

fn next_connection_id() -> usize {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub fn start(config: ProxyConfig, app_state: Proxy) -> Result<()> {
    // Create a new single-threaded runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?;

    std::thread::Builder::new()
        .name("proxy-main".to_string())
        .spawn(move || {
            // Run the proxy_main function in this runtime
            if let Err(err) = rt.block_on(proxy_main(&config, app_state)) {
                error!(
                    "error on {}:{}: {err:?}",
                    config.listen_addr, config.listen_port
                );
            }
        })
        .context("Failed to spawn proxy-main thread")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[test]
    fn test_parse_destination() {
        let base_domain = ".example.com";

        // Test basic app_id only
        let result = parse_destination("myapp.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 80);
        assert!(!result.is_tls);

        // Test app_id with custom port
        let result = parse_destination("myapp-8080.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 8080);
        assert!(!result.is_tls);

        // Test app_id with TLS
        let result = parse_destination("myapp-443s.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 443);
        assert!(result.is_tls);

        // Test app_id with custom port and TLS
        let result = parse_destination("myapp-8443s.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 8443);
        assert!(result.is_tls);

        // Test default port but ends with s
        let result = parse_destination("myapps.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapps");
        assert_eq!(result.port, 80);
        assert!(!result.is_tls);

        // Test default port but ends with s in port part
        let result = parse_destination("myapp-s.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 443);
        assert!(result.is_tls);
    }

    #[test]
    fn test_parse_destination_errors() {
        let base_domain = ".example.com";

        // Test invalid domain suffix
        assert!(parse_destination("myapp.wrong.com", base_domain).is_err());

        // Test multiple subdomains
        assert!(parse_destination("invalid.myapp.example.com", base_domain).is_err());

        // Test invalid port format
        assert!(parse_destination("myapp-65536.example.com", base_domain).is_err());
        assert!(parse_destination("myapp-abc.example.com", base_domain).is_err());

        // Test too many parts
        assert!(parse_destination("myapp-8080-extra.example.com", base_domain).is_err());

        // Test empty app_id
        assert!(parse_destination("-8080.example.com", base_domain).is_err());
        assert!(parse_destination("myapp-8080ss.example.com", base_domain).is_err());
    }

    #[tokio::test]
    async fn test_inbound_stream_tcp_read_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let mut inbound = InboundStream::Tcp(stream);
            inbound.write_all(b"hello vsock").await.unwrap();
            inbound.flush().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = inbound.read(&mut buf).await.unwrap();
            String::from_utf8(buf[..n].to_vec()).unwrap()
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let mut server = server_stream;
        let mut buf = vec![0u8; 64];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello vsock");
        server.write_all(b"echo back").await.unwrap();
        server.shutdown().await.unwrap();

        let response = client_handle.await.unwrap();
        assert_eq!(response, "echo back");
    }

    #[tokio::test]
    async fn test_take_sni_with_inbound_stream() {
        // Verify take_sni works with InboundStream (via impl AsyncRead + Unpin)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Send a TLS ClientHello with SNI "test.example.com"
        let client_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // Minimal TLS ClientHello with SNI extension
            // Record header: ContentType=22 (Handshake), Version=0x0301, Length
            // Handshake: Type=1 (ClientHello)
            let sni_hostname = b"test.example.com";
            let _sni_entry_len = (sni_hostname.len() + 3) as u16;
            let sni_list_len = (sni_hostname.len() + 5) as u16;
            let ext_data_len = (sni_hostname.len() + 7) as u16;
            let extensions_len = ext_data_len + 4; // type(2) + len(2) + data
            let client_hello_body_len = 2 + 32 + 1 + 2 + 1 + 2 + extensions_len;
            let handshake_len = client_hello_body_len + 4; // type(1) + len(3)
            let mut hello = Vec::new();
            // TLS record header
            hello.push(0x16); // ContentType: Handshake
            hello.extend_from_slice(&[0x03, 0x01]); // Version: TLS 1.0
            hello.extend_from_slice(&(handshake_len as u16).to_be_bytes());
            // Handshake header
            hello.push(0x01); // ClientHello
            hello.push(0x00);
            hello.extend_from_slice(&(client_hello_body_len as u16).to_be_bytes());
            // ClientHello body
            hello.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
            hello.extend_from_slice(&[0u8; 32]); // Random
            hello.push(0x00); // Session ID length
            hello.extend_from_slice(&[0x00, 0x02]); // Cipher suites length
            hello.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
            hello.push(0x01); // Compression methods length
            hello.push(0x00); // null compression
            hello.extend_from_slice(&extensions_len.to_be_bytes());
            // SNI extension
            hello.extend_from_slice(&[0x00, 0x00]); // Extension type: SNI
            hello.extend_from_slice(&ext_data_len.to_be_bytes());
            hello.extend_from_slice(&sni_list_len.to_be_bytes());
            hello.push(0x00); // Host name type
            hello.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
            hello.extend_from_slice(sni_hostname);

            stream.write_all(&hello).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let mut inbound = InboundStream::Tcp(server_stream);
        let (sni, _buffer) = take_sni(&mut inbound).await.unwrap();
        assert_eq!(sni.as_deref(), Some("test.example.com"));

        client_handle.await.unwrap();
    }
}
