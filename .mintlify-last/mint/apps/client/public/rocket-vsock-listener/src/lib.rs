use derive_more::Display;
use rocket::listener::{Connection, Endpoint, Listener};
use rocket::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use rocket::{Ignite, Rocket};
use std::pin::Pin;
use std::str::FromStr;
use std::{io, task};
use tokio_vsock as vsock;

use serde::{de, Deserialize, Deserializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VsockError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid vsock address format: {0}")]
    InvalidAddress(String),

    #[error("Invalid protocol, expected 'vsock'")]
    InvalidProtocol,

    #[error("Invalid CID: {0}")]
    InvalidCid(std::num::ParseIntError),

    #[error("Invalid port: {0}")]
    InvalidPort(std::num::ParseIntError),
}

pub struct VsockListener {
    listener: vsock::VsockListener,
    endpoint: VsockEndpoint,
}
pub struct VsockAccept;

#[pin_project::pin_project]
pub struct VsockConnection {
    #[pin]
    stream: vsock::VsockStream,
    addr: vsock::VsockAddr,
}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq)]
#[display("vsock://{cid}:{port}")]
pub struct VsockEndpoint {
    pub cid: u32,
    pub port: u32,
}

impl FromStr for VsockEndpoint {
    type Err = VsockError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix("vsock://")
            .ok_or(VsockError::InvalidAddress(
                "expect format: vsock://<cid>:<port>".into(),
            ))?;

        let (cid, port) = s.split_once(':').ok_or_else(|| {
            VsockError::InvalidAddress("expect format: vsock://<cid>:<port>".into())
        })?;

        let cid = if cid.starts_with("0x") {
            u32::from_str_radix(cid.trim_start_matches("0x"), 16)
        } else {
            cid.parse::<u32>()
        }
        .map_err(VsockError::InvalidCid)?;

        let port = port.parse::<u32>().map_err(VsockError::InvalidPort)?;

        Ok(VsockEndpoint { cid, port })
    }
}

impl<'de> Deserialize<'de> for VsockEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // format:
        // address = "vsock:<cid>"
        // port = "<port>"

        #[derive(Deserialize, Debug)]
        struct Address {
            address: String,
            port: u32,
        }
        let address = Address::deserialize(deserializer)?;
        let (proto, cid) = address.address.split_once(':').ok_or(de::Error::custom(
            VsockError::InvalidAddress("expect format: vsock:<cid>".into()),
        ))?;
        if proto != "vsock" {
            return Err(de::Error::custom(VsockError::InvalidProtocol));
        }
        let cid = if cid.starts_with("0x") {
            u32::from_str_radix(cid.trim_start_matches("0x"), 16)
        } else {
            cid.parse::<u32>()
        }
        .map_err(|e| de::Error::custom(VsockError::InvalidCid(e)))?;
        Ok(VsockEndpoint {
            cid,
            port: address.port,
        })
    }
}

impl Connection for VsockConnection {
    fn endpoint(&self) -> io::Result<Endpoint> {
        let endpoint = VsockEndpoint {
            cid: self.addr.cid(),
            port: self.addr.port(),
        };
        Ok(Endpoint::new(endpoint))
    }
}

impl AsyncRead for VsockConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for VsockConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> task::Poll<Result<usize, io::Error>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

impl Listener for VsockListener {
    type Accept = (vsock::VsockStream, vsock::VsockAddr);

    type Connection = VsockConnection;

    async fn accept(&self) -> io::Result<Self::Accept> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((stream, addr))
    }

    async fn connect(&self, accept: Self::Accept) -> io::Result<Self::Connection> {
        let (stream, addr) = accept;
        Ok(VsockConnection { stream, addr })
    }

    fn endpoint(&self) -> io::Result<Endpoint> {
        Ok(Endpoint::new(self.endpoint))
    }
}

impl VsockListener {
    pub fn bind(endpoint: &VsockEndpoint) -> Result<Self, VsockError> {
        let addr = vsock::VsockAddr::new(endpoint.cid, endpoint.port);
        let listener = vsock::VsockListener::bind(addr)?;
        Ok(Self {
            listener,
            endpoint: *endpoint,
        })
    }

    pub fn extract_endpoint(rocket: &Rocket<Ignite>) -> Result<VsockEndpoint, VsockError> {
        let figment = rocket.figment();
        let endpoint = figment
            .extract::<VsockEndpoint>()
            .map_err(|e| VsockError::InvalidAddress(e.to_string()))?;
        Ok(endpoint)
    }

    pub fn bind_rocket(rocket: &Rocket<Ignite>) -> Result<Self, VsockError> {
        let endpoint = Self::extract_endpoint(rocket)?;
        Self::bind(&endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::figment::Figment;
    use rocket::Config;

    #[test]
    fn test_vsock_endpoint_deserialization() {
        // Test valid vsock endpoint
        let config = Figment::from(Config::default())
            .merge(("address", "vsock:1"))
            .merge(("port", 5000));

        let endpoint = config.extract::<VsockEndpoint>().unwrap();
        assert_eq!(endpoint.cid, 1);
        assert_eq!(endpoint.port, 5000);

        // Test hexadecimal CID
        let config = Figment::from(Config::default())
            .merge(("address", "vsock:0xFF"))
            .merge(("port", 5000));

        let endpoint = config.extract::<VsockEndpoint>().unwrap();
        assert_eq!(endpoint.cid, 255);
        assert_eq!(endpoint.port, 5000);

        // Test invalid protocol
        let config = Figment::from(Config::default())
            .merge(("address", "tcp:1"))
            .merge(("port", 5000));

        assert!(matches!(
            config.extract::<VsockEndpoint>().unwrap_err().to_string(),
            s if s.contains("Invalid protocol")
        ));

        // Test invalid format
        let config = Figment::from(Config::default())
            .merge(("address", "vsock"))
            .merge(("port", 5000));

        assert!(matches!(
            config.extract::<VsockEndpoint>().unwrap_err().to_string(),
            s if s.contains("Invalid vsock address")
        ));
    }

    #[tokio::test]
    async fn test_vsock_listener_bind() {
        let endpoint = VsockEndpoint { cid: 1, port: 5000 };
        let result = VsockListener::bind(&endpoint);

        // Note: This test might fail if you don't have vsock permissions
        // or if the port is already in use
        assert!(result.is_ok());
    }

    #[test]
    fn test_display_format() {
        let endpoint = VsockEndpoint { cid: 1, port: 5000 };
        assert_eq!(endpoint.to_string(), "vsock://1:5000");
    }
}
