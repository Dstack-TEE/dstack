// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Only live jobs/waiters retain keys; a stream of distinct images cannot
/// accumulate an unbounded lock cache.
#[derive(Clone, Default)]
pub(super) struct WorkLocks(Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>);

impl WorkLocks {
    pub(super) async fn lock(&self, key: String) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.0.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            match locks.get(&key).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(Mutex::new(()));
                    locks.insert(key, Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }
}

pub(super) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .context("verifier blocking task failed")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_worker_retains_key_and_does_not_park_executor() {
        let locks = WorkLocks::default();
        let guard = locks.lock("same".into()).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("published");
        let output = path.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(blocking(move || {
            let _guard = guard;
            entered_tx.send(()).unwrap();
            release_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            std::fs::write(output, b"complete")?;
            Ok(())
        }));
        tokio::time::timeout(std::time::Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let _different = locks.lock("different".into()).await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            locks.lock("same".into())
        )
        .await
        .is_err());
        release_tx.send(()).unwrap();
        let _same =
            tokio::time::timeout(std::time::Duration::from_secs(2), locks.lock("same".into()))
                .await
                .unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"complete");
    }

    #[tokio::test]
    async fn idle_keys_are_not_retained() {
        let locks = WorkLocks::default();
        for i in 0..100 {
            drop(locks.lock(i.to_string()).await);
        }
        let _guard = locks.lock("last".into()).await;
        assert_eq!(locks.0.lock().await.len(), 1);
    }
}
