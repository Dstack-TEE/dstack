// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub(crate) struct CacheEntry {
    pub(crate) body: Bytes,
    pub(crate) content_type: String,
    pub(crate) fetched_at: i64,
    pub(crate) expires_at: i64,
}

impl CacheEntry {
    pub(crate) fn is_fresh(&self, now: i64) -> bool {
        self.expires_at > now
    }
}

/// What populated a cache entry. Lets the background refresher re-run the
/// exact upstream query and lets operators identify entries on disk (the
/// filenames themselves are hashes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EntrySource {
    RimId(String),
    OcspRequestB64(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CacheMetadata {
    pub(crate) content_type: String,
    pub(crate) fetched_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) body_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<EntrySource>,
}

#[derive(Debug, Clone)]
pub(crate) struct CacheStore {
    root: PathBuf,
    max_entries_per_namespace: usize,
    maintenance: std::sync::Arc<Mutex<()>>,
}

impl CacheStore {
    pub(crate) async fn new(
        root: impl Into<PathBuf>,
        max_entries_per_namespace: usize,
    ) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("ocsp"))
            .await
            .with_context(|| format!("failed to create {}", root.join("ocsp").display()))?;
        fs::create_dir_all(root.join("rim"))
            .await
            .with_context(|| format!("failed to create {}", root.join("rim").display()))?;
        Ok(Self {
            root,
            max_entries_per_namespace,
            maintenance: Default::default(),
        })
    }

    /// Read an entry. Entries expired for longer than `max_stale_secs` are
    /// removed and reported as absent; entries expired within that window are
    /// returned so callers can decide whether stale data is acceptable
    /// (check with [`CacheEntry::is_fresh`]).
    pub(crate) async fn get(
        &self,
        namespace: &str,
        key: &str,
        now: i64,
        max_stale_secs: i64,
    ) -> Result<Option<CacheEntry>> {
        let (body_path, metadata_path) = self.paths(namespace, key);
        let metadata = match fs::read(&metadata_path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", metadata_path.display()))
            }
        };
        let metadata: CacheMetadata = match serde_json::from_slice(&metadata) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(path = %metadata_path.display(), %error, "discarding invalid cache metadata");
                self.remove_if(namespace, key, |current| {
                    !matches!(current, ReadState::Valid(_))
                })
                .await;
                return Ok(None);
            }
        };
        if metadata.expires_at.saturating_add(max_stale_secs) <= now {
            self.remove_if(namespace, key, move |current| match current {
                ReadState::Valid(metadata) => {
                    metadata.expires_at.saturating_add(max_stale_secs) <= now
                }
                _ => true,
            })
            .await;
            return Ok(None);
        }
        let body = match fs::read(&body_path).await {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.remove_if(namespace, key, |current| {
                    !matches!(current, ReadState::Valid(_))
                })
                .await;
                return Ok(None);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", body_path.display()))
            }
        };
        if hex::encode(Sha256::digest(&body)) != metadata.body_sha256 {
            tracing::warn!(path = %body_path.display(), "discarding cache entry with an invalid digest");
            self.remove_if(namespace, key, |current| {
                !matches!(current, ReadState::Valid(_))
            })
            .await;
            return Ok(None);
        }
        Ok(Some(CacheEntry {
            body: Bytes::from(body),
            content_type: metadata.content_type,
            fetched_at: metadata.fetched_at,
            expires_at: metadata.expires_at,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn put(
        &self,
        namespace: &str,
        key: &str,
        body: &[u8],
        content_type: &str,
        fetched_at: i64,
        expires_at: i64,
        source: Option<EntrySource>,
    ) -> Result<()> {
        let (body_path, metadata_path) = self.paths(namespace, key);
        let metadata = CacheMetadata {
            content_type: content_type.to_string(),
            fetched_at,
            expires_at,
            body_sha256: hex::encode(Sha256::digest(body)),
            source,
        };
        let metadata =
            serde_json::to_vec(&metadata).context("failed to serialize cache metadata")?;

        let _maintenance = self.maintenance.lock().await;
        self.evict_for_insert(namespace, key).await?;
        // Metadata is the commit marker: readers ignore an entry until both
        // the body and its matching metadata have been atomically renamed.
        atomic_write(&body_path, body).await?;
        atomic_write(&metadata_path, &metadata).await?;
        Ok(())
    }

    /// List the metadata of every entry in a namespace, for the background
    /// refresher and the `/info` endpoint. Unreadable metadata is skipped.
    pub(crate) async fn list(&self, namespace: &str) -> Result<Vec<(String, CacheMetadata)>> {
        let directory = self.root.join(namespace);
        let mut entries = fs::read_dir(&directory)
            .await
            .with_context(|| format!("failed to scan {}", directory.display()))?;
        let mut listed = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some(key) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let Some(metadata) = fs::read(&path)
                .await
                .ok()
                .and_then(|data| serde_json::from_slice::<CacheMetadata>(&data).ok())
            else {
                continue;
            };
            listed.push((key.to_string(), metadata));
        }
        Ok(listed)
    }

    /// Remove an entry, but only when a re-read under the maintenance lock
    /// still satisfies `should_remove`. This prevents a stale read from
    /// deleting an entry that a concurrent `put` just refreshed.
    async fn remove_if<F>(&self, namespace: &str, key: &str, should_remove: F)
    where
        F: FnOnce(ReadState) -> bool,
    {
        let _maintenance = self.maintenance.lock().await;
        let (body_path, metadata_path) = self.paths(namespace, key);
        let state = match fs::read(&metadata_path).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => ReadState::Corrupt,
            Ok(data) => match serde_json::from_slice::<CacheMetadata>(&data) {
                Err(_) => ReadState::Corrupt,
                Ok(metadata) => match fs::read(&body_path).await {
                    Err(_) => ReadState::Corrupt,
                    Ok(body) if hex::encode(Sha256::digest(&body)) != metadata.body_sha256 => {
                        ReadState::Corrupt
                    }
                    Ok(_) => ReadState::Valid(metadata),
                },
            },
        };
        if should_remove(state) {
            let _ = fs::remove_file(body_path).await;
            let _ = fs::remove_file(metadata_path).await;
        }
    }

    async fn evict_for_insert(&self, namespace: &str, new_key: &str) -> Result<()> {
        let directory = self.root.join(namespace);
        let mut entries = fs::read_dir(&directory)
            .await
            .with_context(|| format!("failed to scan {}", directory.display()))?;
        let mut metadata = Vec::new();
        let mut replacing = false;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some(key) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            replacing |= key == new_key;
            let fetched_at = fs::read(&path)
                .await
                .ok()
                .and_then(|data| serde_json::from_slice::<CacheMetadata>(&data).ok())
                .map(|metadata| metadata.fetched_at)
                .unwrap_or(i64::MIN);
            metadata.push((fetched_at, key.to_string()));
        }
        if replacing {
            return Ok(());
        }
        metadata.sort_unstable();
        let remove_count = metadata
            .len()
            .saturating_add(1)
            .saturating_sub(self.max_entries_per_namespace);
        for (_, key) in metadata.into_iter().take(remove_count) {
            let (body_path, metadata_path) = self.paths(namespace, &key);
            let _ = fs::remove_file(body_path).await;
            let _ = fs::remove_file(metadata_path).await;
        }
        Ok(())
    }

    fn paths(&self, namespace: &str, key: &str) -> (PathBuf, PathBuf) {
        // Callers pass SHA-256 hex keys, so filenames never contain input from
        // a URL or certificate ID directly.
        let base = self.root.join(namespace).join(key);
        (base.with_extension("body"), base.with_extension("json"))
    }
}

enum ReadState {
    Valid(CacheMetadata),
    Corrupt,
}

async fn atomic_write(path: &Path, value: &[u8]) -> Result<()> {
    let nonce = rand_suffix();
    let temporary = path.with_extension(format!("tmp-{nonce}"));
    fs::write(&temporary, value)
        .await
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    fs::rename(&temporary, path).await.with_context(|| {
        format!(
            "failed to rename {} to {}",
            temporary.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn rand_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn persists_and_expires_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path(), 10).await.unwrap();
        cache
            .put(
                "ocsp",
                "abcd",
                b"response",
                "application/ocsp-response",
                100,
                200,
                None,
            )
            .await
            .unwrap();

        let reopened = CacheStore::new(dir.path(), 10).await.unwrap();
        let entry = reopened.get("ocsp", "abcd", 150, 0).await.unwrap().unwrap();
        assert_eq!(entry.body, &b"response"[..]);
        assert_eq!(entry.fetched_at, 100);
        assert_eq!(entry.expires_at, 200);
        assert!(reopened
            .get("ocsp", "abcd", 200, 0)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn stale_entries_survive_within_the_stale_window() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path(), 10).await.unwrap();
        cache
            .put("rim", "abcd", b"doc", "application/json", 100, 200, None)
            .await
            .unwrap();

        // Within the stale window the entry is returned but not fresh.
        let entry = cache.get("rim", "abcd", 250, 100).await.unwrap().unwrap();
        assert!(!entry.is_fresh(250));
        // Beyond the stale window it is removed.
        assert!(cache.get("rim", "abcd", 301, 100).await.unwrap().is_none());
        assert!(cache.get("rim", "abcd", 150, 100).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_modified_cache_bodies() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path(), 10).await.unwrap();
        cache
            .put("rim", "abcd", b"one", "application/json", 100, 200, None)
            .await
            .unwrap();
        fs::write(dir.path().join("rim/abcd.body"), b"two")
            .await
            .unwrap();
        assert!(cache.get("rim", "abcd", 150, 0).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn evicts_oldest_entry_at_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path(), 1).await.unwrap();
        cache
            .put("rim", "old", b"old", "application/json", 100, 1000, None)
            .await
            .unwrap();
        cache
            .put("rim", "new", b"new", "application/json", 200, 1000, None)
            .await
            .unwrap();
        assert!(cache.get("rim", "old", 300, 0).await.unwrap().is_none());
        assert_eq!(
            cache.get("rim", "new", 300, 0).await.unwrap().unwrap().body,
            &b"new"[..]
        );
    }

    #[tokio::test]
    async fn lists_entries_with_sources() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path(), 10).await.unwrap();
        cache
            .put(
                "rim",
                "abcd",
                b"doc",
                "application/json",
                100,
                200,
                Some(EntrySource::RimId("NV_GPU_DRIVER_GH100_580.1".into())),
            )
            .await
            .unwrap();
        let listed = cache.list("rim").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "abcd");
        assert_eq!(
            listed[0].1.source,
            Some(EntrySource::RimId("NV_GPU_DRIVER_GH100_580.1".into()))
        );
    }
}
