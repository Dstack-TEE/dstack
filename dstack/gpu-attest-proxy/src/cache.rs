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

#[derive(Debug, Serialize, Deserialize)]
struct CacheMetadata {
    content_type: String,
    fetched_at: i64,
    expires_at: i64,
    body_sha256: String,
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

    pub(crate) async fn get(
        &self,
        namespace: &str,
        key: &str,
        now: i64,
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
                self.remove(namespace, key).await;
                return Ok(None);
            }
        };
        if metadata.expires_at <= now {
            self.remove(namespace, key).await;
            return Ok(None);
        }
        let body = match fs::read(&body_path).await {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.remove(namespace, key).await;
                return Ok(None);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", body_path.display()))
            }
        };
        if hex::encode(Sha256::digest(&body)) != metadata.body_sha256 {
            tracing::warn!(path = %body_path.display(), "discarding cache entry with an invalid digest");
            self.remove(namespace, key).await;
            return Ok(None);
        }
        Ok(Some(CacheEntry {
            body: Bytes::from(body),
            content_type: metadata.content_type,
            fetched_at: metadata.fetched_at,
            expires_at: metadata.expires_at,
        }))
    }

    pub(crate) async fn put(
        &self,
        namespace: &str,
        key: &str,
        body: &[u8],
        content_type: &str,
        fetched_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        let (body_path, metadata_path) = self.paths(namespace, key);
        let metadata = CacheMetadata {
            content_type: content_type.to_string(),
            fetched_at,
            expires_at,
            body_sha256: hex::encode(Sha256::digest(body)),
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

    async fn remove(&self, namespace: &str, key: &str) {
        let (body_path, metadata_path) = self.paths(namespace, key);
        let _ = fs::remove_file(body_path).await;
        let _ = fs::remove_file(metadata_path).await;
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
            self.remove(namespace, &key).await;
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
            )
            .await
            .unwrap();

        let reopened = CacheStore::new(dir.path(), 10).await.unwrap();
        let entry = reopened.get("ocsp", "abcd", 150).await.unwrap().unwrap();
        assert_eq!(entry.body, &b"response"[..]);
        assert_eq!(entry.fetched_at, 100);
        assert_eq!(entry.expires_at, 200);
        assert!(reopened.get("ocsp", "abcd", 200).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_modified_cache_bodies() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path(), 10).await.unwrap();
        cache
            .put("rim", "abcd", b"one", "application/json", 100, 200)
            .await
            .unwrap();
        fs::write(dir.path().join("rim/abcd.body"), b"two")
            .await
            .unwrap();
        assert!(cache.get("rim", "abcd", 150).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn evicts_oldest_entry_at_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path(), 1).await.unwrap();
        cache
            .put("rim", "old", b"old", "application/json", 100, 1000)
            .await
            .unwrap();
        cache
            .put("rim", "new", b"new", "application/json", 200, 1000)
            .await
            .unwrap();
        assert!(cache.get("rim", "old", 300).await.unwrap().is_none());
        assert_eq!(
            cache.get("rim", "new", 300).await.unwrap().unwrap().body,
            &b"new"[..]
        );
    }
}
