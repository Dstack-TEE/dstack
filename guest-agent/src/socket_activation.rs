// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Systemd socket activation support for dstack-guest-agent.
//!
//! This module provides utilities for receiving pre-created sockets from systemd
//! via the LISTEN_FDS mechanism, allowing the service to use sockets that survive
//! service restarts.

use std::{io, os::unix::net::UnixListener as StdUnixListener};

use listenfd::ListenFd;
use rocket::listener::{unix::UnixStream, Endpoint, Listener};

/// Socket indices for systemd socket activation.
/// Order matches ListenStream declarations in dstack-guest-agent.socket.
mod socket_index {
    pub const DSTACK: usize = 0;
    pub const TAPPD: usize = 1;
}

/// Systemd-activated sockets passed via LISTEN_FDS.
pub struct ActivatedSockets {
    pub dstack: Option<StdUnixListener>,
    pub tappd: Option<StdUnixListener>,
}

impl ActivatedSockets {
    /// Retrieve activated sockets from systemd environment variables.
    pub fn from_env() -> Self {
        let mut listenfd = ListenFd::from_env();
        Self {
            dstack: listenfd
                .take_unix_listener(socket_index::DSTACK)
                .ok()
                .flatten(),
            tappd: listenfd
                .take_unix_listener(socket_index::TAPPD)
                .ok()
                .flatten(),
        }
    }

    /// Check if any sockets were activated.
    pub fn any_activated(&self) -> bool {
        self.dstack.is_some() || self.tappd.is_some()
    }
}

/// Wrapper for systemd-activated Unix socket that implements rocket's Listener trait.
pub struct ActivatedUnixListener {
    listener: tokio::net::UnixListener,
}

impl ActivatedUnixListener {
    /// Create a new listener from a standard library UnixListener.
    pub fn new(std_listener: StdUnixListener) -> io::Result<Self> {
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(std_listener)?;
        Ok(Self { listener })
    }
}

impl Listener for ActivatedUnixListener {
    type Accept = UnixStream;
    type Connection = UnixStream;

    async fn accept(&self) -> io::Result<Self::Accept> {
        Ok(self.listener.accept().await?.0)
    }

    async fn connect(&self, accept: Self::Accept) -> io::Result<Self::Connection> {
        Ok(accept)
    }

    fn endpoint(&self) -> io::Result<Endpoint> {
        self.listener.local_addr()?.try_into()
    }
}
