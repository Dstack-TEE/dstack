// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Background polling for the TUI.
//!
//! One task per source polls on the shared interval and sends what it got.
//! A failed poll keeps the last good data and marks it with the error, so a
//! node that drops off still shows what was on it. Log fetches run on their
//! own tasks and report back the same way; nothing here ever
//! blocks the caller's loop.

use crate::fmt::now_ms;
use crate::snapshot::NodeSnapshot;
use crate::source::{LogChannel, Source};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRequest {
    pub source: usize,
    pub node: String,
    pub vm_id: String,
    pub channel: LogChannel,
    pub lines: u32,
}

pub enum Command {
    RefreshNow,
    Logs(LogRequest),
}

pub enum Update {
    Nodes {
        source: usize,
        nodes: Vec<NodeSnapshot>,
    },
    Logs {
        req: LogRequest,
        result: Result<String, String>,
    },
}

pub struct Handle {
    pub commands: mpsc::UnboundedSender<Command>,
    pub updates: mpsc::UnboundedReceiver<Update>,
    /// Poll interval in ms; pollers read it before every sleep.
    pub interval_ms: Arc<AtomicU64>,
}

pub fn spawn(sources: Vec<Arc<Source>>, interval_ms: u64) -> Handle {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Command>();
    let (up_tx, up_rx) = mpsc::unbounded_channel();
    let interval = Arc::new(AtomicU64::new(interval_ms));
    let wake = Arc::new(Notify::new());

    for (idx, source) in sources.iter().enumerate() {
        tokio::spawn(poll_loop(
            idx,
            source.clone(),
            interval.clone(),
            wake.clone(),
            up_tx.clone(),
        ));
    }

    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                Command::RefreshNow => wake.notify_waiters(),
                Command::Logs(req) => {
                    let Some(source) = sources.get(req.source).cloned() else {
                        continue;
                    };
                    let tx = up_tx.clone();
                    tokio::spawn(async move {
                        let result = source
                            .logs(&req.vm_id, req.channel, req.lines)
                            .await
                            .map_err(|err| format!("{err:#}"));
                        let _ = tx.send(Update::Logs { req, result });
                    });
                }
            }
        }
    });

    Handle {
        commands: cmd_tx,
        updates: up_rx,
        interval_ms: interval,
    }
}

async fn poll_loop(
    idx: usize,
    source: Arc<Source>,
    interval: Arc<AtomicU64>,
    wake: Arc<Notify>,
    tx: mpsc::UnboundedSender<Update>,
) {
    let mut last: Vec<NodeSnapshot> = Vec::new();
    loop {
        let result = source.poll().await;
        let now = now_ms();
        last = merge_poll(&source, last, result, now);
        if tx
            .send(Update::Nodes {
                source: idx,
                nodes: last.clone(),
            })
            .is_err()
        {
            return;
        }
        let wait = Duration::from_millis(interval.load(Ordering::Relaxed).max(200));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = wake.notified() => {}
        }
    }
}

/// The nodes to show after a poll: fresh ones on success, the previous ones
/// marked with the error on failure.
fn merge_poll(
    source: &Source,
    last: Vec<NodeSnapshot>,
    result: anyhow::Result<Vec<NodeSnapshot>>,
    now: u64,
) -> Vec<NodeSnapshot> {
    match result {
        Ok(mut nodes) => {
            for n in &mut nodes {
                n.polled_at_ms = now;
                n.ok_at_ms = Some(now);
            }
            nodes
        }
        Err(err) => {
            let msg = format!("{err:#}");
            if last.is_empty() {
                return vec![NodeSnapshot {
                    name: source.spec.name.clone(),
                    endpoint: source.endpoint(),
                    polled_at_ms: now,
                    error: Some(msg),
                    ..Default::default()
                }];
            }
            last.into_iter()
                .map(|mut n| {
                    n.polled_at_ms = now;
                    n.error = Some(msg.clone());
                    n
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceSpec;

    fn source() -> Source {
        Source::new(SourceSpec {
            name: "n1".into(),
            url: "http://h:1".into(),
            token: None,
        })
        .unwrap()
    }

    #[test]
    fn failure_keeps_last_good_data() {
        let s = source();
        let good = merge_poll(
            &s,
            vec![],
            Ok(vec![NodeSnapshot {
                name: "n1".into(),
                vms: vec![Default::default()],
                ..Default::default()
            }]),
            1000,
        );
        assert_eq!(good[0].ok_at_ms, Some(1000));
        let bad = merge_poll(&s, good, Err(anyhow::anyhow!("refused")), 2000);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].vms.len(), 1);
        assert_eq!(bad[0].ok_at_ms, Some(1000));
        assert_eq!(bad[0].polled_at_ms, 2000);
        assert_eq!(bad[0].error.as_deref(), Some("refused"));
        assert!(!bad[0].online());
    }

    #[test]
    fn first_failure_makes_placeholder() {
        let s = source();
        let bad = merge_poll(&s, vec![], Err(anyhow::anyhow!("refused")), 5);
        assert_eq!(bad[0].name, "n1");
        assert_eq!(bad[0].endpoint, "http://h:1");
        assert_eq!(bad[0].error.as_deref(), Some("refused"));
    }
}
