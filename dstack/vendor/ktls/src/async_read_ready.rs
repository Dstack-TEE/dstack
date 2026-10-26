use std::{io, task};

pub trait AsyncReadReady {
    /// cf. https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.poll_read_ready
    fn poll_read_ready(&self, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>>;
}

impl AsyncReadReady for tokio::net::TcpStream {
    fn poll_read_ready(&self, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        tokio::net::TcpStream::poll_read_ready(self, cx)
    }
}
