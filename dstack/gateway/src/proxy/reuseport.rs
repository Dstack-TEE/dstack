// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `SO_REUSEPORT` listener groups for the thread-per-core proxy.
//!
//! By default the kernel picks a listener from a reuseport group by hashing the
//! connection's 4-tuple. With a moderate number of long-lived connections that
//! distribution is visibly uneven, and because thread-per-core cannot migrate a
//! connection between runtimes, the cores that drew fewer connections sit idle
//! while the others saturate. Measured at 16 connections over 4 cores, per-core
//! utilisation came out like `[99, 42, 101, 101]` and throughput swung 46%
//! between restarts purely on how the hash fell.
//!
//! `SO_ATTACH_REUSEPORT_CBPF` steering was tried as a fix and measured worse:
//! classic BPF has no maps, so round-robin is not expressible, and the one
//! signal it does expose -- the CPU handling the packet -- collapses the
//! distribution rather than evening it out. Connections are established in a
//! burst, so only the one or two client CPUs active at that moment are sampled,
//! and `cpu % n` sent every connection to the same one or two listeners: 2.3 of
//! 4 cores active and 167k rps against 245k for the plain hash. A real fix needs
//! per-connection state, i.e. an eBPF program with a counter map.
//!
//! What is kept here is binding the group in one place, in order, which keeps
//! listener order deterministic and the setup out of the per-thread path.

use std::net::{SocketAddr, TcpListener};

use anyhow::{bail, Context, Result};

/// Bind `count` `SO_REUSEPORT` listeners on `addr`, in order.
///
/// Returns one listener per worker, in the same order the kernel indexes them.
pub(crate) fn bind_group(addr: SocketAddr, count: usize, backlog: i32) -> Result<Vec<TcpListener>> {
    if count == 0 {
        bail!("reuseport group needs at least one listener");
    }
    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .context("failed to create listening socket")?;
        socket
            .set_reuse_port(true)
            .context("failed to set SO_REUSEPORT")?;
        socket.set_reuse_address(true).ok();
        socket.set_nonblocking(true).ok();
        socket
            .bind(&addr.into())
            .with_context(|| format!("failed to bind {addr}"))?;
        socket.listen(backlog).context("failed to listen")?;
        listeners.push(TcpListener::from(socket));
    }
    Ok(listeners)
}
