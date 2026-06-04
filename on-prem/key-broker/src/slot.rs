// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotBinding {
    pub slot_id: String,
    pub instance_id: String,
    pub app_id: String,
    pub compose_hash: String,
    pub last_seen: u64,
}

pub struct SlotStore {
    inner: Arc<RwLock<HashMap<String, SlotBinding>>>,
    persist_path: std::path::PathBuf,
}

impl SlotStore {
    pub fn new(kms_volume: &Path) -> Self {
        let persist_path = kms_volume.join("slots.json");
        let inner = match std::fs::read_to_string(&persist_path) {
            Ok(s) => serde_json::from_str::<Vec<SlotBinding>>(&s)
                .unwrap_or_default()
                .into_iter()
                .map(|b| (b.slot_id.clone(), b))
                .collect(),
            Err(_) => HashMap::new(),
        };
        Self {
            inner: Arc::new(RwLock::new(inner)),
            persist_path,
        }
    }

    pub async fn find_slot_for_instance(&self, instance_id: &str) -> Option<SlotBinding> {
        let guard = self.inner.read().await;
        guard
            .values()
            .find(|b| b.instance_id == instance_id)
            .cloned()
    }

    /// Allocate a slot for an instance, reusing existing slot if already bound,
    /// otherwise finding a free slot index within [0, slot_quota).
    pub async fn acquire(
        &self,
        app_id: &str,
        instance_id: &str,
        compose_hash: &str,
        slot_quota: usize,
        now_secs: u64,
    ) -> Result<SlotBinding> {
        let mut guard = self.inner.write().await;

        // reuse existing slot for same instance
        if let Some(existing) = guard.values().find(|b| b.instance_id == instance_id) {
            let mut updated = existing.clone();
            updated.last_seen = now_secs;
            updated.compose_hash = compose_hash.to_string();
            guard.insert(updated.slot_id.clone(), updated.clone());
            drop(guard);
            self.persist().await;
            return Ok(updated);
        }

        let used_indices: std::collections::HashSet<usize> = guard
            .values()
            .filter_map(|b| b.slot_id.parse::<usize>().ok())
            .collect();

        let free_index = (0..slot_quota)
            .find(|i| !used_indices.contains(i))
            .ok_or_else(|| anyhow::anyhow!("slot quota exhausted (max {})", slot_quota))?;

        let binding = SlotBinding {
            slot_id: free_index.to_string(),
            instance_id: instance_id.to_string(),
            app_id: app_id.to_string(),
            compose_hash: compose_hash.to_string(),
            last_seen: now_secs,
        };
        guard.insert(binding.slot_id.clone(), binding.clone());
        drop(guard);
        self.persist().await;
        Ok(binding)
    }

    /// Update last_seen for an existing slot. Returns the updated binding.
    pub async fn renew(&self, slot_id: &str, instance_id: &str, now_secs: u64) -> Result<SlotBinding> {
        let mut guard = self.inner.write().await;
        let binding = guard
            .get_mut(slot_id)
            .ok_or_else(|| anyhow::anyhow!("slot {} not found", slot_id))?;
        if binding.instance_id != instance_id {
            return Err(anyhow::anyhow!(
                "instance_id mismatch for slot {}: expected {}, got {}",
                slot_id,
                binding.instance_id,
                instance_id
            ));
        }
        binding.last_seen = now_secs;
        let updated = binding.clone();
        drop(guard);
        self.persist().await;
        Ok(updated)
    }

    /// Remove slots whose last_seen is older than cutoff_secs.
    pub async fn cleanup_stale(&self, cutoff_secs: u64) {
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, b| b.last_seen >= cutoff_secs);
        let removed = before - guard.len();
        if removed > 0 {
            tracing::info!("slot cleanup: removed {} stale slots", removed);
        }
        drop(guard);
        self.persist().await;
    }

    pub async fn all(&self) -> Vec<SlotBinding> {
        self.inner.read().await.values().cloned().collect()
    }

    async fn persist(&self) {
        let guard = self.inner.read().await;
        let bindings: Vec<&SlotBinding> = guard.values().collect();
        match serde_json::to_string_pretty(&bindings) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&self.persist_path, s) {
                    tracing::warn!("failed to persist slots.json: {}", e);
                }
            }
            Err(e) => tracing::warn!("failed to serialize slots: {}", e),
        }
    }
}
