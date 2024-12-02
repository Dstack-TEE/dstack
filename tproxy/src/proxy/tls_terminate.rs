use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use fs_err as fs;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsAcceptor};
use tokio::time::timeout;

use crate::main_service::AppState;
use crate::models::Timeouts;

pub struct TlsTerminateProxy {
    app_state: AppState,
    acceptor: TlsAcceptor,
}

impl TlsTerminateProxy {
    pub fn new(
        app_state: &AppState,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Result<Self> {
        let cert_pem = fs::read(cert.as_ref()).context("failed to read certificate")?;
        let key_pem = fs::read(key.as_ref()).context("failed to read private key")?;
        let certs = CertificateDer::pem_slice_iter(cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse certificate")?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_slice())
            .context("failed to parse private key")?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok(Self {
            app_state: app_state.clone(),
            acceptor,
        })
    }

    pub(crate) async fn proxy(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
        app_id: &str,
        port: Option<u16>,
        timeouts: Option<Timeouts>,
    ) -> Result<()> {
        let port = port.unwrap_or(80);
        let timeouts = timeouts.unwrap_or_default();
        let host = self
            .app_state
            .lock()
            .select_a_host(&app_id)
            .context(format!("tapp {app_id} not found"))?;
        let stream = MergedStream {
            buffer,
            buffer_cursor: 0,
            inbound,
        };
        let mut tls_stream = self
            .acceptor
            .accept(stream)
            .await
            .context("failed to accept tls connection")?;
        let mut outbound = timeout(
            timeouts.connect,
            TcpStream::connect((host.ip, port))
        )
        .await
        .map_err(|_| anyhow::anyhow!("connection timeout"))?
        .context("failed to connect to app")?;
        let _first_byte_timeout = timeout(
            timeouts.first_byte,
            tokio::io::copy_bidirectional(&mut tls_stream, &mut outbound)
        )
        .await
        .map_err(|_| anyhow::anyhow!("first byte timeout"))?
        .context("failed to bridge inbound and outbound")?;
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
