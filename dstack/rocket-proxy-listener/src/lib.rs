// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! A Rocket TCP listener that reads a PROXY protocol header from every
//! connection and reports its source address as the remote endpoint.
//!
//! Headers are read off the accept loop, each with a timeout, so a client that
//! never sends one holds up only its own connection.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use proxy_protocol::{version1 as v1, version2 as v2, ProxyHeader};
use rocket::{
    listener::{tcp::TcpListener, Bind, Connection, Endpoint, Listener},
    tls::TlsListener,
    tokio::io::{AsyncRead, AsyncWrite, ReadBuf},
    Build, Ignite, Rocket,
};
use serde::Deserialize;
use tokio::{
    net::TcpStream,
    sync::{mpsc, Mutex},
    task::JoinHandle,
};
use tracing::warn;

mod header;
pub use header::read_proxy_header;

const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const READY_QUEUE: usize = 128;

/// Launch `rocket` on a [`ProxyListener`] when its config sets
/// `proxy_protocol = true`, with TLS when it has a `tls` section, and on
/// Rocket's default listener otherwise.
pub async fn launch(rocket: Rocket<Build>) -> Result<Rocket<Ignite>, rocket::Error> {
    #[derive(Deserialize)]
    struct Config {
        #[serde(default)]
        proxy_protocol: bool,
    }
    let figment = rocket.figment();
    if !figment.extract::<Config>()?.proxy_protocol {
        return rocket.launch().await;
    }
    if figment.contains("tls") {
        rocket.launch_with::<TlsListener<ProxyListener>>().await
    } else {
        rocket.launch_with::<ProxyListener>().await
    }
}

pub struct ProxyListener {
    local: SocketAddr,
    ready: Mutex<mpsc::Receiver<ProxiedStream>>,
    task: JoinHandle<()>,
}

impl Drop for ProxyListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ProxyListener {
    pub fn new(listener: TcpListener) -> io::Result<Self> {
        let local = listener.local_addr()?;
        let (tx, rx) = mpsc::channel(READY_QUEUE);
        Ok(Self {
            local,
            ready: Mutex::new(rx),
            task: tokio::spawn(accept_loop(listener, tx)),
        })
    }
}

async fn accept_loop(listener: TcpListener, ready: mpsc::Sender<ProxiedStream>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                warn!("failed to accept a connection: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let ready = ready.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(HEADER_TIMEOUT, read_proxy_header(stream)).await {
                Ok(Ok((stream, header))) => {
                    let remote = source_addr(&header).unwrap_or(peer);
                    let _ = ready.send(ProxiedStream { stream, remote }).await;
                }
                Ok(Err(err)) => warn!(%peer, "dropping a connection: {err:#}"),
                Err(_) => warn!(%peer, "dropping a connection: no PROXY header in time"),
            }
        });
    }
}

/// The client address a header carries. `None` for a LOCAL command, such as a
/// proxy's health check, and for unknown or non-IP addresses.
fn source_addr(header: &ProxyHeader) -> Option<SocketAddr> {
    match header {
        ProxyHeader::Version1 { addresses } => match addresses {
            v1::ProxyAddresses::Ipv4 { source, .. } => Some((*source).into()),
            v1::ProxyAddresses::Ipv6 { source, .. } => Some((*source).into()),
            v1::ProxyAddresses::Unknown => None,
        },
        ProxyHeader::Version2 {
            command: v2::ProxyCommand::Proxy,
            addresses,
            ..
        } => match addresses {
            v2::ProxyAddresses::Ipv4 { source, .. } => Some((*source).into()),
            v2::ProxyAddresses::Ipv6 { source, .. } => Some((*source).into()),
            _ => None,
        },
        _ => None,
    }
}

impl Bind for ProxyListener {
    type Error = io::Error;

    async fn bind(rocket: &Rocket<Ignite>) -> Result<Self, Self::Error> {
        let listener = <TcpListener as Bind>::bind(rocket)
            .await
            .map_err(|err| err.either(io::Error::other, |err| err))?;
        Self::new(listener)
    }

    fn bind_endpoint(rocket: &Rocket<Ignite>) -> Result<Endpoint, Self::Error> {
        <TcpListener as Bind>::bind_endpoint(rocket)
            .map_err(|err| err.either(io::Error::other, |err| err))
    }
}

impl Listener for ProxyListener {
    type Accept = ProxiedStream;

    type Connection = ProxiedStream;

    async fn accept(&self) -> io::Result<Self::Accept> {
        self.ready
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::other("the PROXY protocol accept loop stopped"))
    }

    async fn connect(&self, conn: Self::Accept) -> io::Result<Self::Connection> {
        Ok(conn)
    }

    fn endpoint(&self) -> io::Result<Endpoint> {
        Ok(Endpoint::Tcp(self.local))
    }
}

/// A connection whose remote endpoint is the address from its PROXY header.
#[pin_project::pin_project]
pub struct ProxiedStream {
    #[pin]
    stream: TcpStream,
    remote: SocketAddr,
}

impl Connection for ProxiedStream {
    fn endpoint(&self) -> io::Result<Endpoint> {
        Ok(Endpoint::Tcp(self.remote))
    }
}

impl AsyncRead for ProxiedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxiedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}
