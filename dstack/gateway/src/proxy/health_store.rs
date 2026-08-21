// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Health verdicts carried across a restart of this process -- and only that.
//!
//! Health is a per-node observation that WaveKV deliberately does not carry, so
//! without this a gateway restart drops every instance to `Unknown` and holds
//! the fleet out of rotation until each one has been polled again. With
//! staggered poll times across a large app that is long enough to notice.
//!
//! A *reboot* is a different question. Nothing this node believed before the
//! machine went down is evidence about what is running after it: the CVMs it
//! was polling may have been restarted, replaced, or moved while it was gone.
//! So the snapshot is stamped with the kernel's boot id and thrown away when
//! that changes -- the same tmpfs-shaped rule the guest side relies on for its
//! WireGuard key cache, but written down explicitly rather than inherited from
//! where a file happens to live.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::models::HealthState;

/// The kernel's boot id. Changes on every boot and on nothing else.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// What was remembered about one instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct StoredHealth {
    /// The WireGuard key the verdict was observed against.
    ///
    /// A CVM generates a fresh key on every boot, so this doubles as "the same
    /// boot of the same instance". Without it a restarted CVM would inherit a
    /// verdict about the process that came before it -- exactly what holding an
    /// instance at `Unknown` until its first poll exists to prevent.
    pub public_key: String,
    pub state: HealthState,
}

/// Snapshot on disk. Versioned by the boot id it was taken during.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Snapshot {
    boot_id: String,
    instances: BTreeMap<String, StoredHealth>,
}

/// What survived the restart, ready to be consulted while state is rebuilt.
#[derive(Debug, Default)]
pub(crate) struct HealthStore {
    entries: BTreeMap<String, StoredHealth>,
}

impl HealthStore {
    /// Read the snapshot, discarding it unless it was written during this boot.
    ///
    /// Never fails: a snapshot that cannot be read or trusted only costs one
    /// round of polling, so there is nothing here worth refusing to start over.
    pub(crate) fn load(path: &str) -> Self {
        if path.is_empty() {
            return Self::default();
        }
        let Some(boot_id) = boot_id() else {
            warn!("cannot read {BOOT_ID_PATH}; health verdicts will not survive a restart");
            return Self::default();
        };
        let raw = match fs_err::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(err) => {
                warn!("failed to read health snapshot {path}: {err}");
                return Self::default();
            }
        };
        let snapshot: Snapshot = match serde_json::from_str(&raw) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                warn!("failed to parse health snapshot {path}: {err}");
                return Self::default();
            }
        };
        if snapshot.boot_id != boot_id {
            info!("health snapshot predates this boot; re-deriving every verdict");
            return Self::default();
        }
        debug!(
            "restored {} health verdicts from {path}",
            snapshot.instances.len()
        );
        Self {
            entries: snapshot.instances,
        }
    }

    /// The verdict to start an instance at, given what was remembered.
    ///
    /// Falls back to [`HealthState::initial`], so an instance the snapshot does
    /// not cover -- or covers under a different WireGuard key, meaning it has
    /// rebooted since -- is held out of rotation until it answers a poll.
    pub(crate) fn restore(
        &self,
        instance_id: &str,
        public_key: &str,
        health_check: bool,
    ) -> HealthState {
        if !health_check {
            // An instance that is not gated must read `Ungated`, whatever the
            // snapshot says. The snapshot only ever holds gated instances, so a
            // hit here means the record now says otherwise -- an app that opted
            // out, or a record written before the field existed. Trusting the
            // snapshot
            // then would leave the instance both out of rotation (`Unhealthy`
            // is not routable) and out of the poll set (`select_targets`
            // filters on the same flag), with nothing on this node able to lift
            // it until the CVM re-registers.
            return HealthState::Ungated;
        }
        self.entries
            .get(instance_id)
            .filter(|stored| stored.public_key == public_key)
            .map(|stored| stored.state)
            .unwrap_or_else(|| HealthState::initial(health_check))
    }
}

/// Write the snapshot, stamped with the current boot id.
///
/// Best-effort by construction: losing it costs one round of polling.
pub(crate) fn save<'a>(path: &str, entries: impl Iterator<Item = (&'a str, &'a str, HealthState)>) {
    if path.is_empty() {
        return;
    }
    let Some(boot_id) = boot_id() else {
        return;
    };
    let snapshot = Snapshot {
        boot_id,
        instances: entries
            .map(|(id, public_key, state)| {
                (
                    id.to_string(),
                    StoredHealth {
                        public_key: public_key.to_string(),
                        state,
                    },
                )
            })
            .collect(),
    };
    if let Err(err) = write_snapshot(path, &snapshot) {
        warn!("failed to write health snapshot {path}: {err:#}");
    }
}

/// Write via a temporary file in the same directory, then rename.
///
/// A snapshot half-written when the process died would be discarded as
/// unparseable, which is safe but throws away the whole point of having it.
fn write_snapshot(path: &str, snapshot: &Snapshot) -> anyhow::Result<()> {
    let encoded = serde_json::to_vec(snapshot)?;
    // The configured path may point somewhere nothing has created yet. Failing
    // here would make the whole feature a silent no-op plus a warning every
    // round in which a verdict changed.
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs_err::create_dir_all(parent)?;
        }
    }
    let temp = format!("{path}.tmp");
    fs_err::write(&temp, &encoded)?;
    fs_err::rename(&temp, path)?;
    Ok(())
}

/// This boot's id, read once.
fn boot_id() -> Option<String> {
    static BOOT_ID: OnceLock<Option<String>> = OnceLock::new();
    BOOT_ID
        .get_or_init(|| {
            std::fs::read_to_string(BOOT_ID_PATH)
                .ok()
                .map(|id| id.trim().to_string())
                .filter(|id| !id.is_empty())
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_file(dir: &tempfile::TempDir) -> String {
        dir.path()
            .join("instance-health.json")
            .to_str()
            .expect("utf8")
            .to_string()
    }

    fn write_raw(path: &str, boot_id: &str, state: HealthState) {
        let snapshot = Snapshot {
            boot_id: boot_id.to_string(),
            instances: BTreeMap::from([(
                "inst-1".to_string(),
                StoredHealth {
                    public_key: "key-1".to_string(),
                    state,
                },
            )]),
        };
        write_snapshot(path, &snapshot).expect("write");
    }

    #[test]
    fn a_verdict_written_this_boot_is_restored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = snapshot_file(&dir);
        save(
            &path,
            [("inst-1", "key-1", HealthState::Healthy)].into_iter(),
        );
        let store = HealthStore::load(&path);
        assert_eq!(store.restore("inst-1", "key-1", true), HealthState::Healthy);
    }

    /// The reason this store exists at all is that it must NOT survive a
    /// reboot: what this node saw before the machine went down says nothing
    /// about what is running after it.
    #[test]
    fn a_verdict_written_during_an_earlier_boot_is_discarded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = snapshot_file(&dir);
        write_raw(&path, "not-this-boot", HealthState::Healthy);
        let store = HealthStore::load(&path);
        assert_eq!(
            store.restore("inst-1", "key-1", true),
            HealthState::Unknown,
            "a snapshot from a previous boot must not be trusted"
        );
    }

    /// A CVM generates a fresh WireGuard key on every boot, so a changed key is
    /// a restarted app -- the verdict describes a process that is gone.
    #[test]
    fn a_verdict_for_a_different_wireguard_key_is_not_restored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = snapshot_file(&dir);
        save(
            &path,
            [("inst-1", "key-1", HealthState::Healthy)].into_iter(),
        );
        let store = HealthStore::load(&path);
        assert_eq!(store.restore("inst-1", "key-2", true), HealthState::Unknown);
    }

    /// The snapshot only ever holds gated instances, so a hit for one the
    /// record now says is ungated means the record changed underneath it. The
    /// record wins: believing the snapshot would leave the instance out of
    /// rotation *and* out of the poll set, with nothing able to lift it.
    #[test]
    fn a_verdict_is_not_restored_onto_an_instance_that_is_no_longer_gated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = snapshot_file(&dir);
        save(
            &path,
            [("inst-1", "key-1", HealthState::Unhealthy)].into_iter(),
        );
        let store = HealthStore::load(&path);
        assert_eq!(
            store.restore("inst-1", "key-1", false),
            HealthState::Ungated,
            "an ungated instance must stay routable and pollable"
        );
    }

    #[test]
    fn an_instance_the_snapshot_does_not_cover_falls_back_to_initial() {
        let store = HealthStore::default();
        assert_eq!(store.restore("inst-1", "key-1", true), HealthState::Unknown);
        assert_eq!(
            store.restore("inst-1", "key-1", false),
            HealthState::Ungated,
            "an instance that never asked to be polled stays eligible"
        );
    }

    #[test]
    fn an_unreadable_snapshot_is_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = snapshot_file(&dir);
        fs_err::write(&path, b"{ not json").expect("write");
        let store = HealthStore::load(&path);
        assert_eq!(store.restore("inst-1", "key-1", true), HealthState::Unknown);
    }

    /// The configured path can point at a directory nothing has created yet --
    /// the deployed gateway writes under its data volume. Failing there would
    /// make the feature silently inert.
    #[test]
    fn a_missing_parent_directory_is_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join("nested")
            .join("instance-health.json")
            .to_str()
            .expect("utf8")
            .to_string();
        save(
            &path,
            [("inst-1", "key-1", HealthState::Healthy)].into_iter(),
        );
        let store = HealthStore::load(&path);
        assert_eq!(store.restore("inst-1", "key-1", true), HealthState::Healthy);
    }

    #[test]
    fn an_empty_path_disables_the_snapshot() {
        save("", [("inst-1", "key-1", HealthState::Healthy)].into_iter());
        let store = HealthStore::load("");
        assert_eq!(store.restore("inst-1", "key-1", true), HealthState::Unknown);
    }
}
