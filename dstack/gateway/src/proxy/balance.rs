// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Evening out connections across the thread-per-core workers.
//!
//! `SO_REUSEPORT` assigns a connection to a listener by hashing its 4-tuple, and
//! thread-per-core cannot move a connection afterwards, so a core that draws few
//! connections idles while its neighbours saturate. Measured at 16 connections
//! over 4 cores, utilisation came out like `[99, 42, 101, 101]` and throughput
//! varied 46% between restarts on nothing but how the hash fell.
//!
//! Steering the kernel's choice was tried first and failed (see
//! [`super::reuseport`]). This instead lets the accepting core hand the
//! connection to a less loaded one. The cost is a channel send per *rebalanced
//! connection* -- not per connection, and never per request -- so the
//! thread-per-core property that made this model fast in the first place is kept
//! for everything already in flight.
//!
//! This is the same shape as HAProxy's multi-queue accept, which picks the least
//! loaded of three candidate threads and pushes the connection onto its ring.
//! Two of its choices were tried here and did not transfer: capping accepts per
//! wakeup (its `maxaccept`) and routing every connection through the channel even
//! when it stays local both measured within noise. Its shared listening socket
//! measured clearly worse for us -- 227k against 245k at 16 connections -- since
//! every worker's reactor then wakes on every connection. Its own numbers say the
//! same thing from the other side: put HAProxy on per-thread reuseport listeners
//! (`shards by-thread`) and it drops 15%, below our thread-per-core.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// A connection accounted to one core, released when the connection ends.
pub(crate) struct CoreSlot {
    counts: Arc<Vec<AtomicUsize>>,
    core: usize,
}

impl CoreSlot {
    fn claim(counts: Arc<Vec<AtomicUsize>>, core: usize) -> Self {
        counts[core].fetch_add(1, Ordering::Relaxed);
        Self { counts, core }
    }
}

impl Drop for CoreSlot {
    fn drop(&mut self) {
        self.counts[self.core].fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection handed over from another core.
///
/// Carried as a `std::net::TcpStream`, deliberately: a tokio `TcpStream` stays
/// registered with the reactor that accepted it, so moving the object to another
/// core would leave its readiness handling behind and cost a cross-core hop on
/// every read and write for the life of the connection. Handing over the plain
/// socket lets the target core register it with its own reactor.
pub(crate) type Handoff = (std::net::TcpStream, SocketAddr, CoreSlot);

/// Per-core view of the shared connection counts and handoff channels.
pub(crate) struct Balancer {
    counts: Arc<Vec<AtomicUsize>>,
    senders: Arc<Vec<mpsc::Sender<Handoff>>>,
    me: usize,
}

/// Handoffs a core may have waiting before others stop offering it work.
///
/// The queue is bounded on purpose. A core only receives connections while it
/// is the *least* loaded, so in steady state this never fills. What it protects
/// against is a core that stops draining -- wedged or gone: with an unbounded
/// queue the others keep succeeding at `send`, and every connection they hand
/// over sits unserved until `timeouts.total` while its `CoreSlot` keeps the
/// core looking busier, so the queue and the memory behind it only grow. Full
/// means "this core is not actually taking work", and the sender keeps the
/// connection instead.
const HANDOFF_QUEUE: usize = 1024;

/// How far above the least loaded core this one has to be before handing a
/// connection over.
///
/// Proportional, not fixed: a slack of 2 stops a core being starved at 4
/// connections per core but keeps churning at 12, and every migration costs a
/// little locality. Measured against a fixed slack of 2 on passthrough
/// small-request: +6.5% at 16 connections, and the worst-loaded core goes from
/// 81% to 97% busy.
fn migration_threshold(least: usize) -> usize {
    least + 1 + least / 4
}

impl Balancer {
    /// Build one balancer per core, plus the receiver each core listens on.
    pub(crate) fn build(workers: usize) -> (Vec<Self>, Vec<mpsc::Receiver<Handoff>>) {
        let counts = Arc::new(
            (0..workers)
                .map(|_| AtomicUsize::new(0))
                .collect::<Vec<_>>(),
        );
        let mut senders = Vec::with_capacity(workers);
        let mut receivers = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = mpsc::channel(HANDOFF_QUEUE);
            senders.push(tx);
            receivers.push(rx);
        }
        let senders = Arc::new(senders);
        let balancers = (0..workers)
            .map(|me| Self {
                counts: counts.clone(),
                senders: senders.clone(),
                me,
            })
            .collect();
        (balancers, receivers)
    }

    /// Which core should own a freshly accepted connection.
    fn target(&self) -> usize {
        if self.counts.len() < 2 {
            return self.me;
        }
        let mine = self.counts[self.me].load(Ordering::Relaxed);
        let mut best = self.me;
        let mut best_val = mine;
        for (i, c) in self.counts.iter().enumerate() {
            let v = c.load(Ordering::Relaxed);
            if v < best_val {
                best = i;
                best_val = v;
            }
        }
        if mine >= migration_threshold(best_val) {
            best
        } else {
            self.me
        }
    }

    /// Account a newly accepted connection, handing it to a less loaded core if
    /// this one is running ahead.
    ///
    /// Returns the slot to keep alongside the connection when it stays here, or
    /// `None` once the connection has been handed away.
    ///
    /// Handing over is best-effort: every failure path falls back to serving the
    /// connection on this core, because a connection served by a busier core is
    /// strictly better than one that is dropped. The one exception is
    /// [`TcpStream::into_std`], which consumes the stream and closes the socket
    /// when it fails -- there is nothing left to fall back to, so that case is
    /// logged rather than silently counted as a handover.
    pub(crate) fn place(
        &self,
        stream: TcpStream,
        from: SocketAddr,
    ) -> Option<(TcpStream, CoreSlot)> {
        let target = self.target();
        if target == self.me {
            let slot = CoreSlot::claim(self.counts.clone(), self.me);
            return Some((stream, slot));
        }
        // Drop this core's reactor registration before handing the socket over.
        let raw = match stream.into_std() {
            Ok(raw) => raw,
            Err(err) => {
                // `into_std` took ownership, so the socket is already closed.
                warn!("dropping connection from {from}: failed to deregister for handover: {err}");
                return None;
            }
        };
        let slot = CoreSlot::claim(self.counts.clone(), target);
        // `try_send`, not `send`: this runs on the accept path and must not wait
        // on a core that is not draining. See `HANDOFF_QUEUE`.
        let raw = match self.senders[target].try_send((raw, from, slot)) {
            Ok(()) => return None,
            Err(mpsc::error::TrySendError::Full((raw, _, _))) => {
                debug!(
                    "core {target} handoff queue is full; keeping connection on core {}",
                    self.me
                );
                raw
            }
            Err(mpsc::error::TrySendError::Closed((raw, _, _))) => {
                debug!(
                    "core {target} is gone; keeping connection on core {}",
                    self.me
                );
                raw
            }
        };
        match TcpStream::from_std(raw) {
            Ok(stream) => Some((stream, CoreSlot::claim(self.counts.clone(), self.me))),
            Err(err) => {
                // Same as above: `from_std` consumed the socket.
                warn!("dropping connection from {from}: failed to re-adopt after handover: {err}");
                None
            }
        }
    }
}
