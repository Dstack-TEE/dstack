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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

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
pub(crate) type Handoff = (TcpStream, SocketAddr, CoreSlot);

/// Per-core view of the shared connection counts and handoff channels.
pub(crate) struct Balancer {
    counts: Arc<Vec<AtomicUsize>>,
    senders: Arc<Vec<mpsc::UnboundedSender<Handoff>>>,
    me: usize,
}

/// How far above the least loaded core this one has to be before handing a
/// connection over. Two is enough to stop a core being starved while leaving
/// small, transient differences alone -- rebalancing those would just add
/// cross-core traffic for no gain.
const IMBALANCE_SLACK: usize = 2;

impl Balancer {
    /// Build one balancer per core, plus the receiver each core listens on.
    pub(crate) fn build(workers: usize) -> (Vec<Self>, Vec<mpsc::UnboundedReceiver<Handoff>>) {
        let counts = Arc::new(
            (0..workers)
                .map(|_| AtomicUsize::new(0))
                .collect::<Vec<_>>(),
        );
        let mut senders = Vec::with_capacity(workers);
        let mut receivers = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = mpsc::unbounded_channel();
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
        if mine >= best_val.saturating_add(IMBALANCE_SLACK) {
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
    pub(crate) fn place(
        &self,
        stream: TcpStream,
        from: SocketAddr,
    ) -> Option<(TcpStream, CoreSlot)> {
        let target = self.target();
        let slot = CoreSlot::claim(self.counts.clone(), target);
        if target == self.me {
            return Some((stream, slot));
        }
        match self.senders[target].send((stream, from, slot)) {
            Ok(()) => None,
            // The target core is gone; keep the connection rather than drop it.
            Err(mpsc::error::SendError((stream, _, _))) => {
                Some((stream, CoreSlot::claim(self.counts.clone(), self.me)))
            }
        }
    }

}
