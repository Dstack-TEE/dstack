// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! One `info` line per proxied connection, under the `dstack_gateway::access`
//! target, written when the connection ends.
//!
//! On by default; `RUST_LOG=info,dstack_gateway::access=off` turns it off, and
//! then nothing is collected beyond one level check per connection. It replaces
//! turning on the per-connection debug logs to see who connected to what: those
//! are about six lines and a span entered on every poll, which cost 17% of the
//! new-connection rate on a 4-core gateway against 2.5% for this line.

use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::Instant;

use proxy_protocol::ProxyHeader;
use tokio::net::TcpStream;
use tracing::info;

use super::DstInfo;
use crate::pp::DisplayAddr;

const TARGET: &str = "dstack_gateway::access";

pub(crate) struct AccessLog {
    /// A duplicate of the inbound socket, held so its counters can still be
    /// read once the relay has dropped the original. `None` when the log is off.
    socket: Option<OwnedFd>,
    id: usize,
    started: Instant,
    client: Option<ProxyHeader>,
    sni: String,
    app_id: String,
    port: u16,
    route: &'static str,
    instance: String,
}

impl AccessLog {
    pub(crate) fn new(inbound: &TcpStream, id: usize) -> Self {
        let enabled = tracing::enabled!(target: TARGET, tracing::Level::INFO);
        Self {
            socket: enabled
                .then(|| inbound.as_fd().try_clone_to_owned().ok())
                .flatten(),
            id,
            started: Instant::now(),
            client: None,
            sni: String::new(),
            app_id: String::new(),
            port: 0,
            route: "",
            instance: String::new(),
        }
    }

    fn enabled(&self) -> bool {
        self.socket.is_some()
    }

    pub(crate) fn client(&mut self, header: &ProxyHeader) {
        if self.enabled() {
            self.client = Some(header.clone());
        }
    }

    pub(crate) fn sni(&mut self, sni: &str) {
        if self.enabled() {
            self.sni = sni.to_string();
            self.route = "sni";
        }
    }

    pub(crate) fn dst(&mut self, dst: &DstInfo) {
        if self.enabled() {
            self.route = if dst.is_tls {
                "passthrough"
            } else {
                "terminate"
            };
            self.app(&dst.app_id, dst.port);
        }
    }

    pub(crate) fn app(&mut self, app_id: &str, port: u16) {
        if self.enabled() {
            self.app_id = app_id.to_string();
            self.port = port;
        }
    }

    pub(crate) fn instance(&mut self, instance_id: &str) {
        if self.enabled() {
            self.instance = instance_id.to_string();
        }
    }

    pub(crate) fn finish(self, from: std::net::SocketAddr, outcome: impl FnOnce() -> String) {
        let Some(socket) = self.socket else {
            return;
        };
        let (bytes_in, bytes_out) = tcp_bytes(&socket).unwrap_or_default();
        let client = self.client.as_ref().map(|h| DisplayAddr(h).to_string());
        info!(
            target: TARGET,
            conn_id = self.id,
            client = client.as_deref().unwrap_or("-"),
            peer = %from,
            sni = self.sni,
            route = self.route,
            app_id = self.app_id,
            port = self.port,
            instance = self.instance,
            bytes_in,
            bytes_out,
            us = self.started.elapsed().as_micros() as u64,
            outcome = outcome(),
        );
    }
}

/// Bytes received from and acknowledged by the client on this socket, as the
/// kernel counts them. Read here rather than in the relays because spliced and
/// kTLS payloads never pass through this process; for terminated connections it
/// is TLS bytes on the wire.
fn tcp_bytes(socket: &OwnedFd) -> Option<(u64, u64)> {
    // SAFETY: `tcp_info` is plain integers, so all-zero is a valid value.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    // SAFETY: `info` is writable for `len` bytes and the kernel writes at most
    // that many.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some((info.tcpi_bytes_received, info.tcpi_bytes_acked))
}
