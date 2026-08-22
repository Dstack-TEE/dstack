// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Validation boundary between replicated KV records and the local data plane.
//!
//! Every `inst/` record that reaches `ProxyState` — and through it the rendered
//! `wg.conf` — passes through [`accept_instances`] first. The registration-path
//! checks are re-run here because:
//!
//! - a record can arrive from a peer without ever passing through this node's
//!   registration RPC, so its checks are not a boundary for synced data;
//! - last-writer-wins replication cannot enforce invariants that span keys, so
//!   IP and public-key uniqueness have to be re-established on import;
//! - `wg syncconf` rejects the *whole* config file when a single peer key is
//!   malformed, which turns one bad record into a node-wide WireGuard freeze.
//!
//! Validation never aborts the batch: an offending record is skipped and
//! reported, every other instance keeps its routing.
//!
//! Refusals are not all the same, so [`Rejection`] tells the caller which kind
//! it is holding. A record this node cannot make sense of says nothing about
//! whether its instance still exists, so the instance keeps the state the data
//! plane already has; a record that lost an IP or key conflict says the address
//! belongs to someone else, so its instance has to stop being routable.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

use super::{InstanceData, LoadedInstances, MAX_CLOCK_DRIFT_SECS};
use crate::config::WgConfig;
use crate::time::now_secs;

/// A WireGuard public key is 32 raw bytes, base64-encoded by `wg`.
const WG_PUBLIC_KEY_BYTES: usize = 32;

/// Padded base64 of 32 bytes is always 44 characters.
const WG_PUBLIC_KEY_B64_LEN: usize = 44;

/// Upper bound on identifier fields carried in a KV record. Real values are
/// hex-encoded hashes (40-64 chars); the bound keeps a corrupt record that
/// still decodes from pushing an arbitrarily long string into the logs and the
/// rendered config.
const MAX_ID_LEN: usize = 128;

/// Whether a refused record should also cost the instance the state the data
/// plane already holds for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The record is unusable: it fails validation, or its bytes no longer
    /// decode. Either way this node cannot tell what the instance looks like
    /// now, and the last known-good state is a better answer than none — so
    /// whatever the data plane already knows about the instance stays.
    Unusable,
    /// The record is well-formed but lost a uniqueness conflict to an older
    /// registration. Here the winner genuinely owns the IP or the key, so the
    /// loser has to stop being routable; keeping it would put the same address
    /// in `wg.conf` twice and hand it traffic that belongs to the winner.
    LostConflict,
}

/// A record that failed validation, along with the reason.
pub struct RejectedInstance {
    pub instance_id: String,
    pub reason: anyhow::Error,
    pub rejection: Rejection,
}

/// Records accepted for import, plus the ones that were skipped.
pub struct AcceptedInstances {
    pub instances: BTreeMap<String, InstanceData>,
    pub rejected: Vec<RejectedInstance>,
}

impl AcceptedInstances {
    /// Instance IDs that are absent from `instances` only because their record
    /// was unreadable, and whose existing data-plane state must therefore be
    /// left in place rather than treated as a remote deletion.
    pub fn unreadable(&self) -> HashSet<&str> {
        self.rejected
            .iter()
            .filter(|rejected| rejected.rejection == Rejection::Unusable)
            .map(|rejected| rejected.instance_id.as_str())
            .collect()
    }
}

/// Validate a WireGuard public key as `wg` itself would accept it.
pub fn validate_wg_public_key(public_key: &str) -> Result<()> {
    ensure!(!public_key.is_empty(), "public key is empty");
    ensure!(
        !public_key.contains(|c: char| c.is_whitespace() || c.is_control()),
        "public key contains whitespace or control characters"
    );
    // `wg` writes the padded form and accepts nothing else, so the length is
    // part of the format rather than a consequence of the decode below.
    ensure!(
        public_key.len() == WG_PUBLIC_KEY_B64_LEN,
        "public key is {} characters, expected {WG_PUBLIC_KEY_B64_LEN}",
        public_key.len()
    );
    let decoded = STANDARD
        .decode(public_key)
        .map_err(|err| anyhow::anyhow!("public key is not valid base64: {err}"))?;
    ensure!(
        decoded.len() == WG_PUBLIC_KEY_BYTES,
        "public key decodes to {} bytes, expected {WG_PUBLIC_KEY_BYTES}",
        decoded.len()
    );
    Ok(())
}

/// Validate an identifier field: non-empty, bounded, and free of whitespace
/// and control characters. Every identifier a legitimate gateway writes into
/// a KV record satisfies this, so it is also the acceptance bound for
/// operator-supplied instance IDs (e.g. `Admin.RemoveCvm`).
pub(crate) fn validate_id(field: &str, value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "{field} is empty");
    ensure!(
        value.len() <= MAX_ID_LEN,
        "{field} is {} bytes, limit is {MAX_ID_LEN}",
        value.len()
    );
    ensure!(
        !value.contains(|c: char| c.is_whitespace() || c.is_control()),
        "{field} contains whitespace or control characters"
    );
    Ok(())
}

/// Per-record checks that do not depend on any other record.
///
/// `now` is the local wall clock in seconds, taken once per batch so every
/// record in a batch is judged against the same instant.
fn validate_instance(
    wg: &WgConfig,
    now: u64,
    instance_id: &str,
    data: &InstanceData,
) -> Result<()> {
    validate_id("instance_id", instance_id)?;
    validate_id("app_id", &data.app_id)?;
    validate_wg_public_key(&data.public_key)?;
    ensure!(
        data.public_key != wg.public_key,
        "public key belongs to this gateway"
    );
    // The routable network, not this node's allocation share: in a cluster
    // every node carries peers for the CVMs registered on the other nodes, and
    // those hold addresses from the other nodes' shares by design.
    ensure!(
        wg.is_routable_client_ip(data.ip),
        "ip {} is outside the WireGuard network",
        data.ip
    );
    // `reg_time` is the registering node's clock at that one instant, so a
    // clock only has to be wrong once — during the window before chrony
    // converges, or across a time jump — for the future timestamp to be written
    // into the KV permanently. It does not heal when the clock does: both the
    // "gone from KV" pass and `recycle()` age instances with
    // `elapsed().unwrap_or_default()`, which reads a future timestamp as zero
    // age, so the instance is immune to remote deletion and to local recycling
    // until the process restarts. Same horizon as the handshake observations,
    // which are ignored for the same reason.
    let horizon = now.saturating_add(MAX_CLOCK_DRIFT_SECS);
    ensure!(
        data.reg_time <= horizon,
        "reg_time {} is more than {MAX_CLOCK_DRIFT_SECS}s ahead of local time ({now})",
        data.reg_time
    );
    Ok(())
}

/// Filter KV instance records down to the ones safe to apply locally.
///
/// Conflicts on IP or public key are resolved by registration time (oldest
/// wins, ties broken by instance ID) so that every node reaches the same
/// decision from the same KV contents — the local registration path resolves
/// them the same way, by refusing the newcomer.
pub fn accept_instances(wg: &WgConfig, loaded: LoadedInstances) -> AcceptedInstances {
    accept_instances_at(wg, loaded, now_secs())
}

fn accept_instances_at(wg: &WgConfig, loaded: LoadedInstances, now: u64) -> AcceptedInstances {
    let LoadedInstances {
        decoded,
        undecodable,
    } = loaded;

    let mut ordered: Vec<(String, InstanceData)> = decoded.into_iter().collect();
    ordered.sort_by(|(left_id, left), (right_id, right)| {
        left.reg_time
            .cmp(&right.reg_time)
            .then_with(|| left_id.cmp(right_id))
    });

    let mut instances = BTreeMap::new();
    let mut rejected: Vec<RejectedInstance> = undecodable
        .into_iter()
        .map(|(instance_id, reason)| RejectedInstance {
            instance_id,
            reason: anyhow::anyhow!(reason),
            rejection: Rejection::Unusable,
        })
        .collect();
    let mut claimed_ips: HashMap<Ipv4Addr, String> = HashMap::new();
    let mut claimed_keys: HashSet<String> = HashSet::new();

    for (instance_id, data) in ordered {
        let checked = validate_instance(wg, now, &instance_id, &data)
            .map_err(|reason| (Rejection::Unusable, reason))
            .and_then(|()| {
                if let Some(owner) = claimed_ips.get(&data.ip) {
                    return Err((
                        Rejection::LostConflict,
                        anyhow::anyhow!("ip {} is already assigned to instance {owner}", data.ip),
                    ));
                }
                if claimed_keys.contains(&data.public_key) {
                    return Err((
                        Rejection::LostConflict,
                        anyhow::anyhow!("public key is already registered to another instance"),
                    ));
                }
                Ok(())
            });
        if let Err((rejection, reason)) = checked {
            rejected.push(RejectedInstance {
                instance_id,
                reason,
                rejection,
            });
            continue;
        }
        claimed_ips.insert(data.ip, instance_id.clone());
        claimed_keys.insert(data.public_key.clone());
        instances.insert(instance_id, data);
    }

    AcceptedInstances {
        instances,
        rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv4Net;

    /// Wall clock the tests validate against; every fixture `reg_time` below is
    /// well under it unless the test is about the future-timestamp horizon.
    const NOW: u64 = 1_700_000_000;

    fn wg_config() -> WgConfig {
        WgConfig {
            public_key: key(7),
            private_key: "gateway".to_string(),
            listen_port: 51820,
            ip: "10.0.0.1/24".parse::<Ipv4Net>().unwrap(),
            reserved_net: vec!["10.0.0.0/28".parse::<Ipv4Net>().unwrap()],
            client_ip_range: "10.0.0.0/24".parse::<Ipv4Net>().unwrap(),
            interface: "wg0".to_string(),
            config_path: "/tmp/wg.conf".to_string(),
            endpoint: "127.0.0.1:51820".to_string(),
        }
    }

    fn key(seed: u8) -> String {
        STANDARD.encode([seed; WG_PUBLIC_KEY_BYTES])
    }

    fn instance(ip: &str, public_key: &str, reg_time: u64) -> InstanceData {
        InstanceData {
            app_id: "0123456789abcdef".to_string(),
            ip: ip.parse().unwrap(),
            public_key: public_key.to_string(),
            reg_time,
            port_policy: None,
            port_policy_hash: String::new(),
        }
    }

    fn loaded(records: Vec<(&str, InstanceData)>) -> LoadedInstances {
        LoadedInstances {
            decoded: records
                .into_iter()
                .map(|(id, data)| (id.to_string(), data))
                .collect(),
            undecodable: BTreeMap::new(),
        }
    }

    fn accept(records: Vec<(&str, InstanceData)>) -> AcceptedInstances {
        accept_instances_at(&wg_config(), loaded(records), NOW)
    }

    #[test]
    fn accepts_well_formed_records() {
        let accepted = accept(vec![
            ("a", instance("10.0.0.20", &key(1), 100)),
            ("b", instance("10.0.0.21", &key(2), 200)),
        ]);
        assert!(accepted.rejected.is_empty());
        assert_eq!(accepted.instances.len(), 2);
    }

    #[test]
    fn rejects_keys_wg_would_refuse() {
        for bad in [
            "",
            "not base64!",
            &STANDARD.encode([1u8; 16]),
            &format!("{}\nEndpoint = 10.0.0.9:1234", key(3)),
        ] {
            assert!(
                validate_wg_public_key(bad).is_err(),
                "accepted public key {bad:?}"
            );
        }
        assert!(validate_wg_public_key(&key(3)).is_ok());
    }

    #[test]
    fn rejects_ids_unfit_for_kv_keys_and_logs() {
        let too_long = "a".repeat(MAX_ID_LEN + 1);
        for bad in ["", " id", "id ", "in id", "in\nid", too_long.as_str()] {
            assert!(
                validate_id("instance_id", bad).is_err(),
                "accepted id {bad:?}"
            );
        }
        validate_id("instance_id", "peer-instance").unwrap();
        validate_id("instance_id", &"a".repeat(MAX_ID_LEN)).unwrap();
    }

    #[test]
    fn one_bad_record_does_not_drop_the_others() {
        let accepted = accept(vec![
            ("bad-key", instance("10.0.0.20", "not-a-key", 100)),
            ("good", instance("10.0.0.21", &key(2), 200)),
        ]);
        assert_eq!(accepted.rejected.len(), 1);
        assert_eq!(accepted.rejected[0].instance_id, "bad-key");
        assert!(accepted.instances.contains_key("good"));
    }

    #[test]
    fn rejects_addresses_belonging_to_this_gateway() {
        // The gateway's own wg address, an address in its reserved net, and
        // non-unicast garbage must never reach the peer list.
        for ip in ["10.0.0.1", "10.0.0.5", "127.0.0.1", "224.0.0.1", "0.0.0.0"] {
            let accepted = accept(vec![("x", instance(ip, &key(1), 100))]);
            assert!(accepted.instances.is_empty(), "accepted ip {ip}");
        }
    }

    #[test]
    fn rejects_the_gateways_own_public_key() {
        let wg = wg_config();
        let accepted = accept_instances_at(
            &wg,
            loaded(vec![(
                "self-peer",
                instance("10.0.0.20", &wg.public_key, 100),
            )]),
            NOW,
        );
        assert!(accepted.instances.is_empty());
        assert_eq!(accepted.rejected.len(), 1);
    }

    #[test]
    fn duplicate_ip_and_key_claims_resolve_to_the_older_registration() {
        let accepted = accept(vec![
            ("new", instance("10.0.0.20", &key(9), 300)),
            ("old", instance("10.0.0.20", &key(1), 100)),
        ]);
        assert_eq!(accepted.instances.len(), 1);
        assert!(accepted.instances.contains_key("old"));

        let accepted = accept(vec![
            ("new", instance("10.0.0.21", &key(1), 300)),
            ("old", instance("10.0.0.20", &key(1), 100)),
        ]);
        assert_eq!(accepted.instances.len(), 1);
        assert!(accepted.instances.contains_key("old"));
    }

    #[test]
    fn conflict_resolution_does_not_depend_on_iteration_order() {
        let forward = accept(vec![
            ("a", instance("10.0.0.20", &key(1), 100)),
            ("b", instance("10.0.0.20", &key(2), 100)),
        ]);
        let reverse = accept(vec![
            ("b", instance("10.0.0.20", &key(2), 100)),
            ("a", instance("10.0.0.20", &key(1), 100)),
        ]);
        assert_eq!(
            forward.instances.keys().collect::<Vec<_>>(),
            reverse.instances.keys().collect::<Vec<_>>()
        );
        assert!(forward.instances.contains_key("a"));
    }

    #[test]
    fn a_cluster_peers_address_is_not_judged_by_this_nodes_pool() {
        // Every deployment gives each node its own slice, and a CVM is handed
        // every gateway as a WireGuard server — so each node must carry peers
        // holding addresses out of the other nodes' slices. The two shapes in
        // tree disagree on whether those slices sit inside a node's own
        // interface network, so neither the pool nor the interface network can
        // decide this.
        let shapes = [
            // deploy-to-vmm.sh: /18 pools inside a shared /16 interface.
            ("10.8.0.1/16", "10.8.0.0/18", "10.8.0.5", "10.8.64.5"),
            // test-run/cluster.sh and e2e/configs: a /24 per node, and no
            // node's interface covers another's.
            ("10.0.41.1/24", "10.0.41.0/24", "10.0.41.5", "10.0.42.5"),
        ];
        for (ip, pool, mine, peers) in shapes {
            let gateway_addr = ip.split('/').next().unwrap_or_default();
            let wg = WgConfig {
                ip: ip.parse::<Ipv4Net>().unwrap(),
                reserved_net: vec![format!("{gateway_addr}/32").parse::<Ipv4Net>().unwrap()],
                client_ip_range: pool.parse::<Ipv4Net>().unwrap(),
                ..wg_config()
            };
            let accepted = accept_instances(
                &wg,
                loaded(vec![
                    ("mine", instance(mine, &key(1), 100)),
                    ("peers", instance(peers, &key(2), 100)),
                    // Still refused: this gateway's own address.
                    ("steals-gateway-ip", instance(gateway_addr, &key(3), 100)),
                ]),
            );
            assert!(accepted.instances.contains_key("mine"), "{ip}");
            assert!(
                accepted.instances.contains_key("peers"),
                "{ip}: a peer node's instance was refused, which would leave every \
                 gateway serving only its own CVMs"
            );
            assert!(
                !accepted.instances.contains_key("steals-gateway-ip"),
                "{ip}"
            );
        }
    }

    #[test]
    fn rejects_registrations_dated_into_the_future() {
        // A future reg_time reads as zero age in every `elapsed()` check, which
        // makes the instance immune to both remote deletion and local recycling.
        let accepted = accept(vec![
            (
                "future",
                instance("10.0.0.20", &key(1), NOW + MAX_CLOCK_DRIFT_SECS + 1),
            ),
            (
                "skewed",
                instance("10.0.0.21", &key(2), NOW + MAX_CLOCK_DRIFT_SECS),
            ),
        ]);
        assert!(!accepted.instances.contains_key("future"));
        // Drift inside the horizon is ordinary skew between nodes.
        assert!(accepted.instances.contains_key("skewed"));
    }

    #[test]
    fn a_conflict_loser_is_dropped_but_an_unusable_record_keeps_its_instance() {
        // The two rejection kinds drive opposite decisions in the reload pass:
        // a conflict loser must lose its routing to the winner, while an
        // instance whose record we cannot read keeps what the data plane holds.
        let accepted = accept(vec![
            ("loser", instance("10.0.0.20", &key(9), 300)),
            ("winner", instance("10.0.0.20", &key(1), 100)),
            ("malformed", instance("10.0.0.30", "not-a-key", 100)),
        ]);
        let kind = |id: &str| {
            accepted
                .rejected
                .iter()
                .find(|rejected| rejected.instance_id == id)
                .map(|rejected| rejected.rejection)
        };
        assert_eq!(kind("loser"), Some(Rejection::LostConflict));
        assert_eq!(kind("malformed"), Some(Rejection::Unusable));
        assert_eq!(accepted.unreadable(), HashSet::from(["malformed"]));
    }

    #[test]
    fn an_undecodable_record_is_reported_as_unreadable_not_as_absent() {
        let accepted = accept_instances_at(
            &wg_config(),
            LoadedInstances {
                decoded: [("good".to_string(), instance("10.0.0.20", &key(1), 100))]
                    .into_iter()
                    .collect(),
                undecodable: [("corrupt".to_string(), "does not decode".to_string())]
                    .into_iter()
                    .collect(),
            },
            NOW,
        );
        assert!(accepted.instances.contains_key("good"));
        assert_eq!(accepted.unreadable(), HashSet::from(["corrupt"]));
    }

    #[test]
    fn rejects_keys_of_the_wrong_length_before_decoding_them() {
        let oversized = "A".repeat(4096);
        assert!(validate_wg_public_key(&oversized).is_err());
        // 32 bytes unpadded is 43 characters; `wg` writes the padded form.
        assert!(validate_wg_public_key(key(1).trim_end_matches('=')).is_err());
    }
}
