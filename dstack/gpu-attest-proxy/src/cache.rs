// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! File-backed collateral cache. Every entry is one JSON file under
//! `<cache_dir>/<kind>/`, so a proxy restart keeps the cache warm and
//! operators can inspect or evict entries with plain file tools.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// "ocsp" or "rim" — also the subdirectory the entry persists under.
    pub kind: String,
    /// Cache key: hex(CertID DER) for OCSP, the RIM id for RIM.
    pub key: String,
    pub content_type: String,
    #[serde(with = "base64serde")]
    pub body: Vec<u8>,
    /// Original upstream request body for OCSP entries, letting the
    /// background refresher re-run the exact query. RIM refreshes by key.
    #[serde(default, with = "base64serde_opt")]
    pub refresh_body: Option<Vec<u8>>,
    pub fetched_at: i64,
    pub expires_at: i64,
}

impl CacheEntry {
    pub fn is_fresh(&self, now: i64) -> bool {
        now < self.expires_at
    }

    pub fn is_usable_stale(&self, now: i64, max_stale_secs: u64) -> bool {
        now < self.expires_at.saturating_add(max_stale_secs as i64)
    }
}

mod base64serde {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

mod base64serde_opt {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => s.serialize_str(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        text.map(|text| STANDARD.decode(text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

pub struct Cache {
    dir: PathBuf,
    entries: DashMap<String, CacheEntry>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Cache {
    /// Load every well-formed entry from disk; entries past `now +
    /// keep_stale_secs` are dropped instead.
    pub fn load(dir: impl Into<PathBuf>, keep_stale_secs: u64) -> Result<Self> {
        let dir = dir.into();
        let cache = Self {
            dir,
            entries: DashMap::new(),
        };
        let now = now();
        for kind in ["ocsp", "rim"] {
            let kind_dir = cache.dir.join(kind);
            let Ok(read_dir) = fs_err::read_dir(&kind_dir) else {
                continue;
            };
            for file in read_dir.flatten() {
                let path = file.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                match Self::read_entry(&path) {
                    Ok(entry) if entry.is_usable_stale(now, keep_stale_secs) => {
                        cache.entries.insert(map_key(kind, &entry.key), entry);
                    }
                    Ok(_) => {
                        fs_err::remove_file(&path).ok();
                    }
                    Err(err) => {
                        tracing::warn!(
                            "dropping unreadable cache entry {}: {err:#}",
                            path.display()
                        );
                    }
                }
            }
        }
        Ok(cache)
    }

    fn read_entry(path: &Path) -> Result<CacheEntry> {
        let json = fs_err::read(path)?;
        serde_json::from_slice(&json).context("invalid cache entry JSON")
    }

    fn entry_path(&self, kind: &str, key: &str) -> PathBuf {
        let name = hex::encode(Sha256::digest(key.as_bytes()));
        self.dir.join(kind).join(format!("{name}.json"))
    }

    pub fn get(&self, kind: &str, key: &str) -> Option<CacheEntry> {
        self.entries.get(&map_key(kind, key)).map(|e| e.clone())
    }

    /// Insert or replace an entry, persisting it. The entry stays in memory
    /// even if the write fails — availability of the proxy matters more than
    /// durability of one entry.
    pub fn put(&self, entry: CacheEntry) {
        let path = self.entry_path(&entry.kind, &entry.key);
        if let Some(parent) = path.parent() {
            fs_err::create_dir_all(parent).ok();
        }
        match serde_json::to_vec(&entry) {
            Ok(json) => {
                if let Err(err) = fs_err::write(&path, json) {
                    tracing::warn!("failed to persist cache entry {}: {err:#}", path.display());
                }
            }
            Err(err) => tracing::warn!("failed to serialize cache entry: {err:#}"),
        }
        self.entries.insert(map_key(&entry.kind, &entry.key), entry);
    }

    /// Entries whose freshness ends within `margin_secs`, for the background
    /// refresher.
    pub fn expiring_soon(&self, margin_secs: u64) -> Vec<CacheEntry> {
        let deadline = now().saturating_add(margin_secs as i64);
        self.entries
            .iter()
            .filter(|entry| entry.expires_at < deadline)
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn stats(&self) -> (usize, usize) {
        let now = now();
        let fresh = self
            .entries
            .iter()
            .filter(|entry| entry.is_fresh(now))
            .count();
        (fresh, self.entries.len().saturating_sub(fresh))
    }
}

fn map_key(kind: &str, key: &str) -> String {
    format!("{kind}:{key}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: &str, key: &str, expires_at: i64) -> CacheEntry {
        CacheEntry {
            kind: kind.into(),
            key: key.into(),
            content_type: "application/ocsp-response".into(),
            body: b"body".to_vec(),
            refresh_body: Some(b"request".to_vec()),
            fetched_at: now(),
            expires_at,
        }
    }

    #[test]
    fn entries_survive_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::load(dir.path(), 0).unwrap();
        cache.put(entry("ocsp", "aabb", now() + 3600));
        let reloaded = Cache::load(dir.path(), 0).unwrap();
        let entry = reloaded.get("ocsp", "aabb").unwrap();
        assert_eq!(entry.body, b"body");
        assert_eq!(entry.refresh_body, Some(b"request".to_vec()));
    }

    #[test]
    fn load_drops_entries_past_the_stale_window() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::load(dir.path(), 0).unwrap();
        cache.put(entry("rim", "RIM_OLD", now() - 7200));
        let reloaded = Cache::load(dir.path(), 3600).unwrap();
        assert!(reloaded.get("rim", "RIM_OLD").is_none());
    }
}
