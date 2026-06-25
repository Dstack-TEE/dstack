// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! A small `OnceCell`-like cache cell for values that are refreshed by a
//! caller-provided blocking producer.
//!
//! The cell owns the common mechanics: snapshot storage, TTL checks,
//! `spawn_blocking` refreshes, and optional periodic refresh scheduling. The
//! caller owns domain-specific value generation and error handling.

use std::{
    error::Error,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

/// A TTL-bound cell containing the latest successfully produced value.
pub struct TtlCell<T> {
    ttl: Duration,
    entry: RwLock<Option<Entry<T>>>,
    refresh_task_started: AtomicBool,
}

struct Entry<T> {
    value: Arc<T>,
    refreshed_at: Instant,
}

impl<T> Clone for Entry<T> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            refreshed_at: self.refreshed_at,
        }
    }
}

/// A point-in-time view of a cached value.
#[derive(Debug)]
pub struct Snapshot<T> {
    value: Arc<T>,
    refreshed_at: Instant,
    age: Duration,
}

impl<T> Clone for Snapshot<T> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            refreshed_at: self.refreshed_at,
            age: self.age,
        }
    }
}

impl<T> Snapshot<T> {
    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_value(self) -> Arc<T> {
        self.value
    }

    pub fn refreshed_at(&self) -> Instant {
        self.refreshed_at
    }

    pub fn age(&self) -> Duration {
        self.age
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetError {
    Empty,
    Expired { age: Duration, ttl: Duration },
}

impl fmt::Display for GetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "cached cell is empty"),
            Self::Expired { age, ttl } => {
                write!(f, "cached cell value expired: age={age:?}, ttl={ttl:?}")
            }
        }
    }
}

impl Error for GetError {}

#[derive(Debug)]
pub enum RefreshError<E> {
    Join(tokio::task::JoinError),
    Produce(E),
}

impl<E: fmt::Display> fmt::Display for RefreshError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Join(err) => write!(f, "blocking refresh task failed: {err}"),
            Self::Produce(err) => write!(f, "cached cell producer failed: {err}"),
        }
    }
}

impl<E> Error for RefreshError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Join(err) => Some(err),
            Self::Produce(err) => Some(err),
        }
    }
}

impl<T> TtlCell<T> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entry: RwLock::new(None),
            refresh_task_started: AtomicBool::new(false),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns the cached value only if it has not expired.
    pub fn get(&self) -> Result<Snapshot<T>, GetError> {
        let snapshot = self.get_allow_stale()?;
        if snapshot.age() >= self.ttl {
            return Err(GetError::Expired {
                age: snapshot.age(),
                ttl: self.ttl,
            });
        }
        Ok(snapshot)
    }

    /// Returns the last cached value even if it is older than the TTL.
    pub fn get_allow_stale(&self) -> Result<Snapshot<T>, GetError> {
        let entry = match self.entry.read() {
            Ok(entry) => entry,
            Err(poisoned) => poisoned.into_inner(),
        }
        .clone()
        .ok_or(GetError::Empty)?;
        Ok(snapshot(entry))
    }

    pub fn set(&self, value: T) -> Snapshot<T> {
        let entry = Entry {
            value: Arc::new(value),
            refreshed_at: Instant::now(),
        };
        let mut current = match self.entry.write() {
            Ok(entry) => entry,
            Err(poisoned) => poisoned.into_inner(),
        };
        *current = Some(entry.clone());
        snapshot(entry)
    }
}

impl<T> TtlCell<T>
where
    T: Send + Sync + 'static,
{
    /// Runs a blocking producer on Tokio's blocking pool and stores the result.
    pub async fn refresh_blocking<F, E>(&self, producer: F) -> Result<Snapshot<T>, RefreshError<E>>
    where
        F: FnOnce() -> Result<T, E> + Send + 'static,
        E: Send + 'static,
    {
        let value = tokio::task::spawn_blocking(producer)
            .await
            .map_err(RefreshError::Join)?
            .map_err(RefreshError::Produce)?;
        Ok(self.set(value))
    }

    /// Starts one periodic refresh task. Returns `false` if already started.
    pub fn spawn_refresh_task<F, E, H>(
        self: Arc<Self>,
        interval: Duration,
        producer: F,
        on_error: H,
    ) -> bool
    where
        F: Fn() -> Result<T, E> + Send + Sync + 'static,
        E: Send + 'static,
        H: Fn(RefreshError<E>) + Send + Sync + 'static,
    {
        if self.refresh_task_started.swap(true, Ordering::Relaxed) {
            return false;
        }

        let producer = Arc::new(producer);
        let on_error = Arc::new(on_error);
        tokio::spawn(async move {
            loop {
                let producer = Arc::clone(&producer);
                if let Err(err) = self.refresh_blocking(move || producer()).await {
                    on_error(err);
                }
                tokio::time::sleep(interval).await;
            }
        });
        true
    }
}

fn snapshot<T>(entry: Entry<T>) -> Snapshot<T> {
    Snapshot {
        age: entry.refreshed_at.elapsed(),
        refreshed_at: entry.refreshed_at,
        value: entry.value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_empty_before_first_set() {
        let cell = TtlCell::<u32>::new(Duration::from_secs(1));
        assert_eq!(cell.get().unwrap_err(), GetError::Empty);
    }

    #[test]
    fn returns_cached_value() {
        let cell = TtlCell::new(Duration::from_secs(1));
        cell.set(42);
        assert_eq!(*cell.get().unwrap().value(), 42);
    }

    #[test]
    fn enforces_ttl() {
        let cell = TtlCell::new(Duration::ZERO);
        cell.set(42);
        assert!(matches!(cell.get(), Err(GetError::Expired { .. })));
        assert_eq!(*cell.get_allow_stale().unwrap().value(), 42);
    }

    #[tokio::test]
    async fn refreshes_with_blocking_producer() {
        let cell = TtlCell::new(Duration::from_secs(1));
        let snapshot = cell.refresh_blocking(|| Ok::<_, ()>(7)).await.unwrap();
        assert_eq!(*snapshot.value(), 7);
        assert_eq!(*cell.get().unwrap().value(), 7);
    }
}
