// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! A bounded, coalescing worker for blocking WireGuard updates.

use std::{
    sync::mpsc::Receiver,
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Context, Result};

const BATCH_WINDOW: Duration = Duration::from_millis(25);
const RETRY_DELAY: Duration = Duration::from_secs(1);

pub(super) fn spawn(
    rx: Receiver<()>,
    apply: impl FnMut() -> Result<()> + Send + 'static,
) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("gateway-wg-apply".into())
        .spawn(move || run(rx, apply, BATCH_WINDOW, RETRY_DELAY))
        .context("failed to start WireGuard apply worker")
}

fn run(
    rx: Receiver<()>,
    mut apply: impl FnMut() -> Result<()>,
    batch_window: Duration,
    retry_delay: Duration,
) {
    let mut retry = false;
    loop {
        if retry {
            // Requests must not bypass the backoff when the interface or disk
            // is broken. Keep the capacity-one pending request while sleeping.
            thread::sleep(retry_delay);
        } else {
            if rx.recv().is_err() {
                return;
            }
            // Fixed window, not a sliding debounce: continuous registrations
            // cannot postpone convergence forever.
            thread::sleep(batch_window);
        }
        // Consume before rendering, never after: a request arriving during an
        // apply must leave a wakeup for the next snapshot.
        match rx.try_recv() {
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            Ok(()) | Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        retry = match apply() {
            Ok(()) => false,
            Err(err) => {
                tracing::error!("failed to apply WireGuard config; retrying: {err:#}");
                true
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{channel, sync_channel},
        Arc,
    };

    #[test]
    fn burst_is_bounded_and_update_during_apply_is_not_lost() {
        let (tx, rx) = sync_channel(1);
        let (started_tx, started_rx) = channel();
        let (release_tx, release_rx) = channel();
        let state = Arc::new(AtomicUsize::new(1));
        let worker_state = state.clone();
        let worker = thread::spawn(move || {
            run(
                rx,
                || {
                    started_tx
                        .send(worker_state.load(Ordering::SeqCst))
                        .unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                },
                Duration::ZERO,
                Duration::ZERO,
            );
        });
        tx.try_send(()).unwrap();
        assert_eq!(started_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
        for value in 2..=10_000 {
            state.store(value, Ordering::SeqCst);
            let _ = tx.try_send(());
        }
        release_tx.send(()).unwrap();
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            10_000
        );
        release_tx.send(()).unwrap();
        drop(tx);
        worker.join().unwrap();
        assert!(started_rx.try_recv().is_err());
    }

    #[test]
    fn failed_apply_retries_without_another_request() {
        let (tx, rx) = sync_channel(1);
        let (done_tx, done_rx) = channel();
        let worker = thread::spawn(move || {
            let mut attempts = 0;
            run(
                rx,
                || {
                    attempts += 1;
                    if attempts == 1 {
                        anyhow::bail!("injected apply failure");
                    }
                    done_tx.send(attempts).unwrap();
                    Ok(())
                },
                Duration::ZERO,
                Duration::from_millis(10),
            );
        });
        tx.send(()).unwrap();
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
        drop(tx);
        worker.join().unwrap();
    }

    #[test]
    fn disconnected_queue_stops_retrying() {
        let (tx, rx) = sync_channel(1);
        let (done_tx, done_rx) = channel();
        let worker = thread::spawn(move || {
            run(
                rx,
                || {
                    done_tx.send(()).unwrap();
                    anyhow::bail!("injected persistent failure");
                },
                Duration::ZERO,
                Duration::from_millis(10),
            );
        });
        tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(tx);
        worker.join().unwrap();
    }
}
