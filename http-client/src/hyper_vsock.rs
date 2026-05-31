// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use hyper::{body::Body, rt::ReadBufCursor, Uri};
use hyper_util::{
    client::legacy::{
        connect::{Connected, Connection},
        Client,
    },
    rt::{TokioExecutor, TokioIo},
};
use pin_project_lite::pin_project;
use std::{
    future::Future,
    io,
    io::Error,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_vsock::VsockAddr;
use tower_service::Service;

pin_project! {
    /// Wrapper around [`tokio_vsock::VsockStream`].
    #[derive(Debug)]
    pub struct VsockStream {
        #[pin]
        vsock_stream: tokio_vsock::VsockStream,
    }
}

impl VsockStream {
    async fn connect(cid: u32, port: u32) -> io::Result<Self> {
        let vsock_stream = tokio_vsock::VsockStream::connect(VsockAddr::new(cid, port)).await?;
        Ok(Self { vsock_stream })
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().vsock_stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().vsock_stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().vsock_stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        self.project().vsock_stream.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.vsock_stream.is_write_vectored()
    }
}

impl hyper::rt::Write for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.project().vsock_stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().vsock_stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().vsock_stream.poll_shutdown(cx)
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().vsock_stream.poll_read(cx, buf)
    }
}

impl hyper::rt::Read for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), Error>> {
        let mut t = TokioIo::new(self.project().vsock_stream);
        Pin::new(&mut t).poll_read(cx, buf)
    }
}

/// the `[VsockConnector]` can be used to construct a `[hyper::Client]` which can
/// speak to a vsock domain socket.
///
/// # Note
/// If you don't need access to the low-level `[hyper::Client]` builder
/// interface, consider using the `[VsockClientExt]` trait instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct VsockConnector;

impl Unpin for VsockConnector {}

impl Service<Uri> for VsockConnector {
    type Response = VsockStream;
    type Error = io::Error;
    #[allow(clippy::type_complexity)]
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn call(&mut self, req: Uri) -> Self::Future {
        let fut = async move {
            let (cid, port) = parse_vsock_host(&req)?;
            VsockStream::connect(cid, port).await
        };

        Box::pin(fut)
    }

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Connection for VsockStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

fn invalid_input(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn parse_vsock_host(uri: &Uri) -> Result<(u32, u32), io::Error> {
    if uri.scheme_str() != Some("vsock") {
        return Err(invalid_input("invalid URL, scheme must be vsock"));
    }

    let cid = uri
        .host()
        .ok_or(invalid_input("invalid URL, host must be present"))?
        .parse::<u32>()
        .map_err(|e| invalid_input(&format!("invalid URL, host must be a valid u32: {e}")))?;
    let port = uri
        .port()
        .ok_or(invalid_input("invalid URL, port must be present"))?
        .as_str()
        .parse::<u32>()
        .map_err(|e| invalid_input(&format!("invalid URL, port must be a valid u32: {e}")))?;

    Ok((cid, port))
}

/// Extension trait for constructing a hyper HTTP client over a Vsock
pub trait VsockClientExt<B: Body + Send> {
    /// Construct a client which speaks HTTP over a Vsock domain socket
    #[must_use]
    fn vsock() -> Client<VsockConnector, B>
    where
        B::Data: Send,
    {
        Client::builder(TokioExecutor::new()).build(VsockConnector)
    }
}

impl<B: Body + Send> VsockClientExt<B> for Client<VsockConnector, B> {}
