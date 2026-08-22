// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::{load_config_figment, Config, MutualConfig};
use crate::kv::PortFlags;
use crate::proxy::port_policy::is_port_allowed;
use crate::time::encode_ts;
use base64::Engine as _;
use std::sync::atomic::Ordering;
use tempfile::TempDir;

struct TestState {
    proxy: Proxy,
    _temp_dir: TempDir,
}

impl std::ops::Deref for TestState {
    type Target = Proxy;
    fn deref(&self) -> &Self::Target {
        &self.proxy
    }
}

async fn create_test_state() -> TestState {
    create_test_state_with(|_| {}).await
}

async fn create_test_state_with(tweak: impl FnOnce(&mut Config)) -> TestState {
    let figment = load_config_figment(None);
    let mut config = figment.focus("core").extract::<Config>().unwrap();
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    config.sync.data_dir = temp_dir.path().to_string_lossy().to_string();
    // the default points at /etc/wireguard/wg0.conf, so anything that calls
    // `reconfigure` would write to the host's real WireGuard config.
    config.wg.config_path = temp_dir
        .path()
        .join("wg.conf")
        .to_string_lossy()
        .into_owned();
    tweak(&mut config);
    let options = ProxyOptions {
        config,
        my_app_id: None,
        tls_config: TlsConfig {
            certs: "".to_string(),
            key: "".to_string(),
            mutual: MutualConfig {
                ca_certs: "".to_string(),
            },
        },
    };
    let proxy = Proxy::new(options)
        .await
        .expect("failed to create app state");
    TestState {
        proxy,
        _temp_dir: temp_dir,
    }
}

#[tokio::test]
async fn test_empty_config() {
    let state = create_test_state().await;
    let wg_config = state.lock().generate_wg_config().unwrap();
    insta::assert_snapshot!(wg_config);
}

/// The rendered config contains the interface's WireGuard private key, so the
/// file must not be readable by anyone else. It used to be written with the
/// default mode, landing at `0o666 & !umask`.
#[cfg(unix)]
#[tokio::test]
async fn wg_config_is_written_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let state = create_test_state().await;
    let path = state.lock().config.wg.config_path.clone();

    // `reconfigure` also runs `wg syncconf`, which fails without a real
    // interface — that failure is logged rather than propagated, so the write
    // is still exercised here.
    state.lock().reconfigure().expect("reconfigure failed");

    let rendered = std::fs::read_to_string(&path).expect("wg config was not written");
    assert!(
        rendered.contains("PrivateKey"),
        "test would be vacuous: the config carries no key"
    );

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "wg config holds a private key, got mode {mode:o}"
    );
}

/// Deterministic stand-in for a real WireGuard public key.
///
/// Registration and the wg-config renderer both reject keys `wg` itself would
/// refuse, so test fixtures have to be 32 base64-encoded bytes like the real
/// thing.
fn test_pubkey(label: &str) -> String {
    let mut key = [0u8; 32];
    for (slot, byte) in key.iter_mut().zip(label.bytes().cycle()) {
        *slot = byte;
    }
    base64::engine::general_purpose::STANDARD.encode(key)
}

fn policy(restrict: bool, ports: &[u16]) -> PortPolicy {
    PortPolicy {
        ports: ports
            .iter()
            .map(|p| (*p, PortFlags { pp: false }))
            .collect(),
        restrict_mode: restrict,
    }
}

#[test]
fn test_validate_wireguard_public_key() {
    assert!(crate::kv::import::validate_wg_public_key(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    .is_ok());
    assert!(crate::kv::import::validate_wg_public_key("not-a-wireguard-key").is_err());
    assert!(crate::kv::import::validate_wg_public_key("AQID").is_err());
}

#[tokio::test]
async fn test_invalid_wireguard_public_key_does_not_register() {
    let state = create_test_state().await;
    let result = state.do_register_cvm("app", "instance", "invalid", "compose", None);

    assert!(result.is_err());
    assert!(!state.lock().state.instances.contains_key("instance"));
}

#[tokio::test]
async fn test_wireguard_public_key_cannot_be_reused_by_another_instance() {
    const PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let state = create_test_state().await;
    state
        .lock()
        .new_client_by_id("instance-1", "app", PUBLIC_KEY, "compose", None)
        .unwrap();

    let result = state.do_register_cvm("app", "instance-2", PUBLIC_KEY, "compose", None);

    assert!(result.is_err());
    assert!(!state.lock().state.instances.contains_key("instance-2"));
}

#[tokio::test]
async fn test_port_policy_restrict_mode_allows_listed_only() {
    let state = create_test_state().await;
    state
        .lock()
        .new_client_by_id(
            "inst-allow",
            "app-allow",
            &test_pubkey("pubkey-allow"),
            "hash-allow",
            Some(policy(true, &[8080, 9090])),
        )
        .unwrap();
    assert!(is_port_allowed(&state.proxy, "inst-allow", 8080).is_ok());
    assert!(is_port_allowed(&state.proxy, "inst-allow", 9090).is_ok());
    assert!(is_port_allowed(&state.proxy, "inst-allow", 7070).is_err());
}

#[tokio::test]
async fn test_port_policy_disabled_allows_all() {
    let state = create_test_state().await;
    state
        .lock()
        .new_client_by_id(
            "inst-open",
            "app-open",
            &test_pubkey("pubkey-open"),
            "hash-open",
            // restrict_mode = false, but with `ports` listed: still open.
            Some(policy(false, &[8080])),
        )
        .unwrap();
    assert!(is_port_allowed(&state.proxy, "inst-open", 8080).is_ok());
    assert!(is_port_allowed(&state.proxy, "inst-open", 9999).is_ok());
}

#[tokio::test]
async fn test_port_policy_unknown_fails_closed() {
    let state = create_test_state().await;
    // Register without a policy (legacy CVM): policy is None.
    state
        .lock()
        .new_client_by_id(
            "inst-legacy",
            "app-legacy",
            &test_pubkey("pubkey-legacy"),
            "hash-legacy",
            None,
        )
        .unwrap();
    assert!(is_port_allowed(&state.proxy, "inst-legacy", 8080).is_err());
}

#[tokio::test]
async fn test_port_policy_unknown_instance_bypasses_check() {
    let state = create_test_state().await;
    // No registration for "localhost" (or any other id) → not a CVM, allow.
    assert!(is_port_allowed(&state.proxy, "localhost", 8080).is_ok());
    assert!(is_port_allowed(&state.proxy, "never-registered", 80).is_ok());
}

#[tokio::test]
async fn test_admin_override_takes_precedence() {
    let state = create_test_state().await;
    // Instance reports a permissive policy (port 8080 allowed).
    state
        .lock()
        .new_client_by_id(
            "inst-ovr",
            "app-ovr",
            &test_pubkey("pubkey-ovr"),
            "hash-ovr",
            Some(policy(true, &[8080])),
        )
        .unwrap();
    assert!(is_port_allowed(&state.proxy, "inst-ovr", 8080).is_ok());
    // Admin overrides with a stricter policy (only port 9090 allowed).
    state
        .lock()
        .set_admin_port_policy("inst-ovr", policy(true, &[9090]))
        .unwrap();
    assert!(is_port_allowed(&state.proxy, "inst-ovr", 8080).is_err());
    assert!(is_port_allowed(&state.proxy, "inst-ovr", 9090).is_ok());
}

#[tokio::test]
async fn test_admin_override_can_open_what_instance_restricts() {
    let state = create_test_state().await;
    // Instance restricts to nothing (effectively a lockdown).
    state
        .lock()
        .new_client_by_id(
            "inst-lock",
            "app-lock",
            &test_pubkey("pubkey-lock"),
            "hash-lock",
            Some(policy(true, &[])),
        )
        .unwrap();
    assert!(is_port_allowed(&state.proxy, "inst-lock", 8080).is_err());
    // Admin opens it back up (restrict_mode=false → allow all).
    state
        .lock()
        .set_admin_port_policy("inst-lock", policy(false, &[]))
        .unwrap();
    assert!(is_port_allowed(&state.proxy, "inst-lock", 8080).is_ok());
}

#[tokio::test]
async fn test_clear_admin_override_reverts_to_instance_policy() {
    let state = create_test_state().await;
    state
        .lock()
        .new_client_by_id(
            "inst-revert",
            "app-revert",
            &test_pubkey("pubkey-revert"),
            "hash-revert",
            Some(policy(true, &[8080])),
        )
        .unwrap();
    state
        .lock()
        .set_admin_port_policy("inst-revert", policy(true, &[9090]))
        .unwrap();
    assert!(is_port_allowed(&state.proxy, "inst-revert", 9090).is_ok());
    state.lock().clear_admin_port_policy("inst-revert").unwrap();
    // Back to instance policy: 8080 yes, 9090 no.
    assert!(is_port_allowed(&state.proxy, "inst-revert", 8080).is_ok());
    assert!(is_port_allowed(&state.proxy, "inst-revert", 9090).is_err());
}

#[tokio::test]
async fn test_admin_override_unknown_instance_errors() {
    let state = create_test_state().await;
    let err = state
        .lock()
        .set_admin_port_policy("never-registered", policy(true, &[8080]))
        .unwrap_err();
    assert!(format!("{err:#}").contains("not found"));
    let err = state
        .lock()
        .clear_admin_port_policy("never-registered")
        .unwrap_err();
    assert!(format!("{err:#}").contains("not found"));
}

#[tokio::test]
async fn test_admin_override_survives_compose_hash_change() {
    let state = create_test_state().await;
    // Initial registration with one compose_hash.
    state
        .lock()
        .new_client_by_id(
            "inst-upgrade",
            "app-upgrade",
            &test_pubkey("pubkey-upgrade"),
            "hash-v1",
            Some(policy(true, &[8080])),
        )
        .unwrap();
    state
        .lock()
        .set_admin_port_policy("inst-upgrade", policy(true, &[9090]))
        .unwrap();
    // Re-register with a different compose_hash (simulating an app upgrade).
    // Instance reports a new permissive policy.
    state
        .lock()
        .new_client_by_id(
            "inst-upgrade",
            "app-upgrade",
            &test_pubkey("pubkey-upgrade"),
            "hash-v2",
            Some(policy(true, &[7070, 8080])),
        )
        .unwrap();
    // Admin override must still be in effect.
    assert!(is_port_allowed(&state.proxy, "inst-upgrade", 9090).is_ok());
    assert!(is_port_allowed(&state.proxy, "inst-upgrade", 7070).is_err());
    assert!(is_port_allowed(&state.proxy, "inst-upgrade", 8080).is_err());
}

#[tokio::test]
async fn test_config() {
    let state = create_test_state().await;
    let mut info = state
        .lock()
        .new_client_by_id(
            "test-id-0",
            "app-id-0",
            &test_pubkey("test-pubkey-0"),
            "",
            None,
        )
        .unwrap();

    info.reg_time = SystemTime::UNIX_EPOCH;
    insta::assert_debug_snapshot!(info);
    let mut info1 = state
        .lock()
        .new_client_by_id(
            "test-id-1",
            "app-id-1",
            &test_pubkey("test-pubkey-1"),
            "",
            None,
        )
        .unwrap();
    info1.reg_time = SystemTime::UNIX_EPOCH;
    insta::assert_debug_snapshot!(info1);
    let wg_config = state.lock().generate_wg_config().unwrap();
    insta::assert_snapshot!(wg_config);
}

#[tokio::test]
async fn gateway_top_n_batch_007_cache_health_and_invalidation() {
    let state = create_test_state().await;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut proxy = state.lock();
        for index in 0..4 {
            proxy
                .new_client_by_id(
                    &format!("top-instance-{index}"),
                    "top-app",
                    &test_pubkey(&format!("top-key-{index}")),
                    "",
                    Some(policy(false, &[])),
                )
                .unwrap();
        }
        proxy.handshake_cache.set_for_test(BTreeMap::from([
            (test_pubkey("top-key-0"), now),
            (test_pubkey("top-key-1"), now - 1),
            (test_pubkey("top-key-2"), now - 2),
            (test_pubkey("top-key-3"), now - 3600),
        ]));
        let selected = proxy.select_top_n_hosts("top-app").unwrap();
        let selected_ids = selected
            .iter()
            .map(|row| row.instance_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            selected_ids,
            vec!["top-instance-0", "top-instance-1", "top-instance-2"]
        );
        assert_eq!(proxy.state.top_n.len(), 1);

        proxy.handshake_cache.set_for_test(BTreeMap::from([
            (test_pubkey("top-key-0"), now - 3600),
            (test_pubkey("top-key-1"), now - 3600),
            (test_pubkey("top-key-2"), now - 3600),
            (test_pubkey("top-key-3"), now),
        ]));
        let cached = proxy.select_top_n_hosts("top-app").unwrap();
        assert_eq!(
            cached
                .iter()
                .map(|row| row.instance_id.as_str())
                .collect::<Vec<_>>(),
            selected_ids
        );

        proxy
            .new_client_by_id(
                "top-instance-4",
                "top-app",
                &test_pubkey("top-key-4"),
                "",
                Some(policy(false, &[])),
            )
            .unwrap();
        assert!(proxy.state.top_n.is_empty());
        proxy.handshake_cache.set_for_test(BTreeMap::from([
            (test_pubkey("top-key-0"), now - 3600),
            (test_pubkey("top-key-1"), now - 3600),
            (test_pubkey("top-key-2"), now - 3600),
            (test_pubkey("top-key-3"), now),
            (test_pubkey("top-key-4"), now - 1),
        ]));
        let refreshed = proxy.select_top_n_hosts("top-app").unwrap();
        assert_eq!(refreshed.len(), 2);
        assert!(refreshed
            .iter()
            .any(|row| row.instance_id == "top-instance-4"));

        proxy.remove_instance("top-instance-4").unwrap();
        assert!(proxy.state.top_n.is_empty());
        let direct = proxy.select_top_n_hosts("top-instance-3").unwrap();
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].instance_id, "top-instance-3");
        assert!(proxy.select_top_n_hosts("other-app").is_err());
    }
}

/// Register `count` instances of `app` and mark every handshake fresh, so the
/// only thing that can keep an instance out of a selection is the gate.
fn register_ready_instances(proxy: &mut ProxyState, app: &str, count: usize) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut handshakes = BTreeMap::new();
    for index in 0..count {
        let id = format!("{app}-{index}");
        let key = test_pubkey(&format!("{app}-key-{index}"));
        proxy
            .new_client_by_id(&id, app, &key, "", Some(policy(false, &[])))
            .unwrap();
        handshakes.insert(key, now);
    }
    proxy.handshake_cache.set_for_test(handshakes);
}

fn selected_ids(group: &AddressGroup) -> Vec<String> {
    group
        .iter()
        .map(|row| row.instance_id.clone())
        .collect::<Vec<_>>()
}

/// The gate exists so an operator can pull a misbehaving instance out of the
/// rotation *and still reach it*. Dropping it from app-id selection while
/// leaving instance-id routing untouched is the whole feature.
#[tokio::test]
async fn gating_an_instance_removes_it_from_rotation_but_keeps_it_directly_reachable() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "gated-app", 3);

    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("gated-app").unwrap()).len(),
        3
    );

    proxy.set_ready("gated-app-1", false).unwrap();

    let after = selected_ids(&proxy.select_top_n_hosts("gated-app").unwrap());
    assert_eq!(after, vec!["gated-app-0", "gated-app-2"]);

    // ... but addressing it directly still resolves, which is what makes
    // debugging a quarantined instance possible.
    let direct = proxy.select_top_n_hosts("gated-app-1").unwrap();
    assert_eq!(selected_ids(&direct), vec!["gated-app-1"]);
}

/// The selection cache holds a pre-gate snapshot for up to `cache_top_n`.
/// An emergency cut-off that takes 30s to apply is not an emergency cut-off.
#[tokio::test]
async fn gating_an_instance_invalidates_the_selection_cache() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "cache-app", 2);

    proxy.select_top_n_hosts("cache-app").unwrap();
    assert_eq!(proxy.state.top_n.len(), 1, "selection should be cached");

    proxy.set_ready("cache-app-0", false).unwrap();
    assert!(
        proxy.state.top_n.is_empty(),
        "closing the gate must drop the cached selection"
    );
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("cache-app").unwrap()),
        vec!["cache-app-1"]
    );
}

/// Mark `instance_id`'s tunnel as long dead while leaving the others alone.
fn expire_handshake(proxy: &mut ProxyState, instance_id: &str) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = proxy.state.instances[instance_id].public_key.clone();
    let mut handshakes = proxy
        .latest_handshakes(None)
        .unwrap()
        .into_iter()
        .map(|(pk, (ts, _))| (pk, ts))
        .collect::<BTreeMap<_, _>>();
    handshakes.insert(key, now.saturating_sub(3600));
    proxy.handshake_cache.set_for_test(handshakes);
}

/// The warning exists to tell an operator they just took the app offline. An
/// instance nobody gated but whose tunnel is dead is not cover: selection will
/// not route to it either. Counting it as cover silences the warning in the one
/// case it is for.
#[tokio::test]
async fn draining_the_last_live_instance_warns_even_with_ungated_dead_ones() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "half-dead", 2);
    expire_handshake(&mut proxy, "half-dead-1");

    // Nobody gated -1, so a gate-only count sees cover in it.
    assert!(proxy.state.instances["half-dead-1"].is_ready());
    assert_eq!(proxy.count_eligible_instances("half-dead").unwrap(), 1);

    proxy.set_ready("half-dead-0", false).unwrap();
    let warning = proxy
        .drain_warning("half-dead-0", "half-dead", true, false)
        .unwrap();
    assert!(
        warning.is_some_and(|message| message.contains("no instance eligible")),
        "draining onto a dead instance must still warn"
    );
}

/// The message on a failed gate write asks the operator to retry. Warning on
/// the resulting count alone makes that retry claim the instance was the last
/// ready one -- a second time, about an instance that was already gated.
#[tokio::test]
async fn re_gating_an_already_gated_instance_does_not_warn_again() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "twice", 1);

    proxy.set_ready("twice-0", false).unwrap();
    assert!(
        proxy
            .drain_warning("twice-0", "twice", true, false)
            .unwrap()
            .is_some(),
        "closing the last gate is worth saying once"
    );

    assert!(
        proxy
            .drain_warning("twice-0", "twice", false, false)
            .unwrap()
            .is_none(),
        "an instance that was already gated was not the last ready one"
    );
}

/// Health checks are inference and may be wrong, so they fail open. The
/// operator gate is an instruction, so it does not: gating every instance
/// means the app refuses new connections rather than quietly serving them.
#[tokio::test]
async fn gating_every_instance_refuses_traffic_instead_of_failing_open() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "drained-app", 2);

    proxy.set_ready("drained-app-0", false).unwrap();
    proxy.set_ready("drained-app-1", false).unwrap();

    assert!(
        proxy.select_top_n_hosts("drained-app").unwrap().is_empty(),
        "an operator draining every instance must be obeyed, not overridden"
    );

    proxy.set_ready("drained-app-1", true).unwrap();
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("drained-app").unwrap()),
        vec!["drained-app-1"]
    );
}

/// Instance ids are derived from attestation and survive reboots, so a
/// re-registration is usually the same box coming back. It must not rejoin the
/// rotation on its own.
#[tokio::test]
async fn the_gate_survives_re_registration() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "reboot-app", 2);
    proxy.set_ready("reboot-app-0", false).unwrap();

    // Same instance id, same key: a reboot re-running registration.
    proxy
        .new_client_by_id(
            "reboot-app-0",
            "reboot-app",
            &test_pubkey("reboot-app-key-0"),
            "",
            Some(policy(false, &[])),
        )
        .unwrap();

    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("reboot-app").unwrap()),
        vec!["reboot-app-1"],
        "a rebooted instance must stay out of rotation until an operator says otherwise"
    );
}

/// The re-registration above is local, so the node applying it already holds
/// the gate. The case that used to lose it is a peer: the gate rode in the
/// instance record, every node rewrites that record in full from its own
/// memory on every registration, and `gateway_checker` re-registers every 180s
/// -- so a node the gate had not reached yet published a record without it and
/// won on last-write. The record it publishes now cannot carry the gate at all.
#[tokio::test]
async fn a_re_registration_by_a_node_that_never_saw_the_gate_cannot_drop_it() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_ready_instances(&mut proxy, "race-app", 2);
        proxy.set_ready("race-app-0", false).unwrap();
    }

    // What that peer would publish: the whole instance record, rebuilt from a
    // memory copy holding no gate, with a newer reg_time so it wins.
    {
        let mut proxy = state.lock();
        let unaware = InstanceInfo {
            ready: None,
            admin_port_policy: None,
            reg_time: SystemTime::now(),
            ..proxy.state.instances["race-app-0"].clone()
        };
        state
            .kv_store
            .sync_instance("race-app-0", &InstanceData::from(&unaware))
            .unwrap();
        // ... and this node forgets it too, so only the store can answer.
        proxy.state.instances.get_mut("race-app-0").unwrap().ready = None;
    }
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let mut proxy = state.lock();
    assert_eq!(
        proxy.state.instances["race-app-0"].ready,
        Some(false),
        "the gate has its own key; a re-registration must not be able to reach it"
    );
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("race-app").unwrap()),
        vec!["race-app-1"]
    );
}

/// The data plane, not just the store: an override an older build left inside
/// the instance record has to be in force from the first load, before anything
/// has had a chance to move it.
#[tokio::test]
async fn an_override_left_in_the_instance_record_still_reaches_the_data_plane() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_ready_instances(&mut proxy, "legacy-app", 2);
    }
    // Rewrite the record the way the previous build wrote it: the operator
    // fields inside, and no `admin/` record anywhere.
    {
        let proxy = state.lock();
        let existing = proxy.state.instances["legacy-app-0"].clone();
        let legacy = LegacyRecord {
            app_id: existing.app_id,
            ip: existing.ip,
            public_key: existing.public_key,
            reg_time: encode_ts(existing.reg_time),
            port_policy: existing.port_policy,
            port_policy_hash: existing.port_policy_hash,
            admin_port_policy: Some(policy(true, &[8443])),
            ready: Some(false),
        };
        state
            .kv_store
            .persistent()
            .write()
            .put(
                crate::kv::keys::inst("legacy-app-0"),
                crate::kv::encode(&legacy).unwrap(),
            )
            .unwrap();
    }

    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    let migrated = &proxy.state.instances["legacy-app-0"];
    assert_eq!(migrated.ready, Some(false));
    assert_eq!(migrated.admin_port_policy, Some(policy(true, &[8443])));
    assert_eq!(
        state.kv_store.load_all_instance_overrides().decoded["legacy-app-0"].ready,
        Some(false),
        "and the reload should have moved them to their own key"
    );
}

/// The service-level counterpart of the KV test: an operator setting the gate
/// here must not discard a port-policy override a peer set and this node has
/// not applied yet. Two overrides in one record made that a whole-value
/// conflict; two keys make them independent.
#[tokio::test]
async fn setting_the_gate_does_not_discard_a_peers_port_policy_override() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_ready_instances(&mut proxy, "split-app", 2);
    }
    // A peer's override, in the store but not yet in this node's memory.
    state
        .kv_store
        .sync_instance_port_policy_override(
            "split-app-0",
            &AdminPortPolicy {
                policy: Some(policy(true, &[8443])),
            },
        )
        .unwrap();
    state.lock().set_ready("split-app-0", false).unwrap();

    let loaded = state.kv_store.load_all_instance_overrides();
    assert_eq!(
        loaded.decoded["split-app-0"],
        AdminOverrides {
            port_policy: Some(policy(true, &[8443])),
            ready: Some(false),
        },
        "the gate write must not have taken the port-policy override with it"
    );
}

/// The two overrides have a key each, so one of them existing says nothing
/// about the other. Falling back to the instance record per instance rather
/// than per key means an operator who gates an instance mid-upgrade drops the
/// port-policy override that has not been moved across yet -- silently
/// widening the ports the app serves, which is the failure the split exists to
/// remove.
///
/// The reload path hides this: it migrates before it reads, so the key it would
/// have fallen back for already exists by then. Startup does not -- nothing may
/// be written before the WaveKV bootstrap -- so the merge itself has to be
/// right, which is what this asserts.
#[test]
fn one_override_key_existing_does_not_answer_for_the_other() {
    let mut current = LoadedOverrides::default();
    // A peer gated the instance through the new key. Only that key exists.
    current.decoded.insert(
        "half-moved".to_string(),
        AdminOverrides {
            ready: Some(false),
            port_policy: None,
        },
    );
    current.present.insert(
        "half-moved".to_string(),
        BTreeSet::from([crate::kv::keys::ADMIN_READY.to_string()]),
    );
    // The port-policy override is still where the previous build left it.
    let legacy = BTreeMap::from([(
        "half-moved".to_string(),
        AdminOverrides {
            ready: Some(true),
            port_policy: Some(policy(true, &[8443])),
        },
    )]);

    let effective = effective_overrides("half-moved", &current, &legacy);
    assert_eq!(
        effective.ready,
        Some(false),
        "the gate key exists, so it answers -- not the stale copy"
    );
    assert_eq!(
        effective.port_policy,
        Some(policy(true, &[8443])),
        "the port-policy key does not exist, so the instance record still answers"
    );
}

/// The other half of the same rule: a key that exists and says "cleared" is an
/// answer. Reading the stale copy there would undo the clear.
#[test]
fn a_cleared_override_is_an_answer_not_an_absence() {
    let mut current = LoadedOverrides::default();
    current
        .decoded
        .insert("cleared".to_string(), AdminOverrides::default());
    current.present.insert(
        "cleared".to_string(),
        BTreeSet::from([crate::kv::keys::ADMIN_PORT_POLICY.to_string()]),
    );
    let legacy = BTreeMap::from([(
        "cleared".to_string(),
        AdminOverrides {
            ready: None,
            port_policy: Some(policy(true, &[8443])),
        },
    )]);

    assert_eq!(
        effective_overrides("cleared", &current, &legacy).port_policy,
        None,
        "the operator cleared it; the instance record must not put it back"
    );
}

/// The instance record as the build before the override key wrote it.
#[derive(serde::Serialize)]
struct LegacyRecord {
    app_id: String,
    ip: std::net::Ipv4Addr,
    public_key: String,
    reg_time: u64,
    port_policy: Option<crate::kv::PortPolicy>,
    port_policy_hash: String,
    admin_port_policy: Option<crate::kv::PortPolicy>,
    ready: Option<bool>,
}

/// The test above takes the early-return branch of `new_client_by_id`, where
/// the in-memory record is reused untouched -- so it says nothing about the
/// rebuild branch, which reconstructs the record. Dropping the operator
/// overrides there left the whole suite green, which is why this test exists.
///
/// That branch runs when the recorded IP is no longer inside
/// `wg.client_ip_range` -- an operator renumbering the range, or a record
/// restored from a differently-configured gateway. The instance is rebuilt from
/// the previous one, and anything held only in the record has to survive that.
#[tokio::test]
async fn both_operator_overrides_survive_the_ip_rebuild_path() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "rebuild-app", 2);
    proxy.set_ready("rebuild-app-0", false).unwrap();
    proxy
        .set_admin_port_policy("rebuild-app-0", policy(true, &[8443]))
        .unwrap();

    // Put the recorded IP outside the configured range, so re-registering takes
    // the rebuild branch instead of the early return.
    let stale_ip: Ipv4Addr = "192.0.2.7".parse().unwrap();
    assert!(
        !proxy.valid_ip(stale_ip),
        "the test IP must be out of range"
    );
    let old_ip = proxy.state.instances["rebuild-app-0"].ip;
    proxy.state.instances.get_mut("rebuild-app-0").unwrap().ip = stale_ip;
    proxy.state.allocated_addresses.remove(&old_ip);
    proxy.state.allocated_addresses.insert(stale_ip);

    proxy
        .new_client_by_id(
            "rebuild-app-0",
            "rebuild-app",
            &test_pubkey("rebuild-app-key-0"),
            "",
            Some(policy(false, &[])),
        )
        .unwrap();

    let rebuilt = proxy.state.instances["rebuild-app-0"].clone();
    assert!(
        proxy.valid_ip(rebuilt.ip),
        "the rebuild path should have reallocated an in-range IP"
    );
    assert_eq!(
        rebuilt.ready,
        Some(false),
        "the operator's traffic gate was dropped by the rebuild"
    );
    assert_eq!(
        rebuilt.admin_port_policy,
        Some(policy(true, &[8443])),
        "the operator's port-policy override was dropped by the rebuild"
    );
}

/// `persist_instance_overrides` returns a `Result` for exactly one caller:
/// `set_ready`, whose API tells an operator the gate is in force. Swallowing
/// that error left the whole suite green, so nothing pinned the one behaviour
/// the signature exists for.
#[tokio::test]
async fn a_gate_that_could_not_be_stored_is_reported_as_such() {
    let state = create_test_state().await;
    state
        .kv_store
        .fail_writes_for_test(&[crate::kv::InstanceRecord::Gate]);
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "durable-app", 1);

    let err = proxy
        .set_ready("durable-app-0", false)
        .expect_err("a failed store write must not be reported as success");
    let message = format!("{err:#}");
    assert!(
        message.contains("not durable"),
        "the operator has to be told the setting did not stick: {message}"
    );

    // Still in force locally, deliberately: the operator's intent applies to
    // the next connection even though it is not durable.
    assert_eq!(proxy.state.instances["durable-app-0"].ready, Some(false));
}

/// `connect_top_n = 0` takes the random-selection path, which carries its own
/// copy of the filter.
#[tokio::test]
async fn the_random_selection_path_honours_the_gate() {
    let state = create_test_state_with(|config| config.proxy.connect_top_n = 0).await;
    let mut proxy = state.lock();
    register_ready_instances(&mut proxy, "random-app", 2);
    proxy.set_ready("random-app-0", false).unwrap();

    for _ in 0..16 {
        assert_eq!(
            selected_ids(&proxy.select_top_n_hosts("random-app").unwrap()),
            vec!["random-app-1"]
        );
    }
}

/// The gate reaches other gateways through WaveKV, not through the RPC. A node
/// that learns about it on a reload has to drop the selection it cached before
/// the change, or it keeps feeding the gated instance for up to `cache_top_n`.
#[tokio::test]
async fn a_gate_arriving_through_kv_invalidates_the_cached_selection() {
    let state = create_test_state().await;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut proxy = state.lock();
        register_ready_instances(&mut proxy, "peer-app", 2);
        proxy.select_top_n_hosts("peer-app").unwrap();
        assert_eq!(proxy.state.top_n.len(), 1, "selection should be cached");
    }

    // A peer gated peer-app-0 and the override record reached us through sync.
    state
        .kv_store
        .sync_instance_gate("peer-app-0", &InstanceGate { ready: false })
        .unwrap();
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let mut proxy = state.lock();
    assert!(
        proxy.state.top_n.is_empty(),
        "a gate arriving through KV must drop the cached selection"
    );
    proxy.handshake_cache.set_for_test(BTreeMap::from([
        (test_pubkey("peer-app-key-0"), now),
        (test_pubkey("peer-app-key-1"), now),
    ]));
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("peer-app").unwrap()),
        vec!["peer-app-1"]
    );
}

/// Every live key in either store whose name contains `instance_id`.
///
/// Scanned rather than listed, so a per-instance key added later without a
/// matching delete shows up here instead of leaking quietly.
fn live_keys_naming(state: &TestState, instance_id: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (key, entry) in state
        .kv_store
        .persistent()
        .read()
        .iter_all_including_tombstones()
    {
        if key.contains(instance_id) && !entry.is_deleted() {
            found.push(key.clone());
        }
    }
    for (key, entry) in state
        .kv_store
        .ephemeral()
        .read()
        .iter_all_including_tombstones()
    {
        if key.contains(instance_id) && !entry.is_deleted() {
            found.push(key.clone());
        }
    }
    found.sort();
    found
}

/// Nothing that names a CVM may outlive it. The gate especially: instance ids
/// are recycled, so one left behind would quarantine whatever registers under
/// the id next.
///
/// The deletes are issued unconditionally so a failure in one cannot strand the
/// others, which is only worth anything if they are all actually issued.
#[tokio::test]
async fn removing_an_instance_leaves_nothing_behind_that_names_it() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_ready_instances(&mut proxy, "gone-app", 2);
        proxy.set_ready("gone-app-0", false).unwrap();
        proxy
            .set_admin_port_policy("gone-app-0", policy(true, &[8443]))
            .unwrap();
        // Seed the two ephemeral records as well, or the assertion below passes
        // whether or not the deletes are issued.
        state.kv_store.sync_connections("gone-app-0", 3).unwrap();
        state
            .kv_store
            .sync_instance_handshake("gone-app-0", 1)
            .unwrap();
    }

    let node = state.kv_store.my_node_id();
    let before = live_keys_naming(&state, "gone-app-0");
    assert_eq!(
        before,
        vec![
            "admin/gone-app-0/port_policy".to_string(),
            "admin/gone-app-0/ready".to_string(),
            format!("conn/gone-app-0/{node}"),
            format!("handshake/gone-app-0/{node}"),
            "inst/gone-app-0".to_string(),
        ],
        "the fixture must seed every per-instance key, or the assertion below \
         is vacuous"
    );

    state.lock().remove_instance("gone-app-0").unwrap();

    assert!(
        live_keys_naming(&state, "gone-app-0").is_empty(),
        "left behind: {:?}",
        live_keys_naming(&state, "gone-app-0")
    );
    // The sibling is untouched: a delete is per instance, not per app.
    assert!(!live_keys_naming(&state, "gone-app-1").is_empty());
}

/// Selection handing over an empty group means every instance was ruled out
/// before the port policy ever looked -- an operator drained the app, or none
/// passed the handshake filter. Blaming the port policy sends whoever reads the
/// log at the wrong subsystem, and the port it names was never examined.
#[tokio::test]
async fn an_empty_candidate_group_names_the_reason_selection_had() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_ready_instances(&mut proxy, "drain-all", 2);
        proxy.set_ready("drain-all-0", false).unwrap();
        expire_handshake(&mut proxy, "drain-all-1");
    }
    let mut proxy = state.lock();
    let empty = proxy.select_top_n_hosts("drain-all").unwrap();
    assert!(empty.is_empty());
    drop(proxy);

    let err =
        crate::proxy::port_policy::filter_allowed_addresses(&state.proxy, empty, "drain-all", 443)
            .unwrap_err()
            .to_string();
    assert!(!err.contains("port"), "the port was never checked: {err}");
    assert!(
        err.contains("1 gated out by an operator"),
        "the gated instance should be accounted for: {err}"
    );
    assert!(
        err.contains("1 with no recent WireGuard handshake"),
        "the dead instance should be accounted for: {err}"
    );
}

#[tokio::test]
async fn gating_an_unregistered_instance_is_an_error() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    assert!(proxy.set_ready("never-registered", false).is_err());
}

/// Write a record straight into the KV store, bypassing registration, the way
/// a peer's sync round would.
fn sync_from_peer(state: &TestState, instance_id: &str, ip: &str, public_key: &str) {
    sync_from_peer_at(state, instance_id, ip, public_key, 1);
}

fn sync_from_peer_at(
    state: &TestState,
    instance_id: &str,
    ip: &str,
    public_key: &str,
    reg_time: u64,
) {
    state
        .kv_store
        .sync_instance(
            instance_id,
            &InstanceData {
                app_id: "peer-app".to_string(),
                ip: ip.parse().unwrap(),
                public_key: public_key.to_string(),
                reg_time,
                port_policy: None,
                port_policy_hash: String::new(),
            },
        )
        .unwrap();
}

#[tokio::test]
async fn a_poisoned_peer_record_costs_only_its_own_instance() {
    let state = create_test_state().await;
    sync_from_peer(&state, "good", "10.0.0.41", &test_pubkey("good-key"));
    // A key `wg` refuses makes `wg syncconf` reject the entire config file, so
    // this record must never reach ProxyState or the rendered peer list.
    sync_from_peer(
        &state,
        "poisoned",
        "10.0.0.42",
        "not-a-key\nEndpoint = 1.2.3.4:1",
    );
    // The gateway's own wg address, claimed by an instance.
    sync_from_peer(
        &state,
        "steals-gateway-ip",
        "10.0.0.1",
        &test_pubkey("other"),
    );
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    assert!(proxy.state.instances.contains_key("good"));
    assert!(!proxy.state.instances.contains_key("poisoned"));
    assert!(!proxy.state.instances.contains_key("steals-gateway-ip"));

    let rendered = proxy.generate_wg_config().unwrap();
    assert!(rendered.contains(&test_pubkey("good-key")));
    assert!(!rendered.contains("Endpoint = 1.2.3.4:1"));
}

#[tokio::test]
async fn a_cvm_registered_on_another_node_becomes_a_wg_peer_here() {
    let state = create_test_state().await;
    // What a peer node allocated out of its own slice. `test-run/cluster.sh`
    // and the e2e configs give each node a /24 of its own, so a peer's address
    // is outside this node's pool *and* outside its interface network — yet
    // every CVM is handed every gateway as a WireGuard server, so this node
    // still has to carry it.
    let peer_ip = "10.0.42.5";
    assert!(!state.config.wg.is_valid_client_ip(peer_ip.parse().unwrap()));
    sync_from_peer(&state, "peer-node-cvm", peer_ip, &test_pubkey("far"));
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    assert!(
        proxy.state.instances.contains_key("peer-node-cvm"),
        "refusing a peer node's instance leaves each gateway serving only its own CVMs"
    );
    let rendered = proxy.generate_wg_config().unwrap();
    assert!(rendered.contains(peer_ip), "peer missing from wg.conf");
}

#[tokio::test]
async fn an_instance_deleted_on_another_node_stops_being_routable_here() {
    let state = create_test_state().await;
    sync_from_peer(
        &state,
        "peer-instance",
        "10.0.0.40",
        &test_pubkey("peer-key"),
    );
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    assert!(state.lock().state.instances.contains_key("peer-instance"));

    // The remote node recycled the CVM; until the deletion is applied locally
    // the deregistered instance keeps receiving proxied traffic.
    state
        .kv_store
        .sync_delete_instance("peer-instance")
        .unwrap();
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    assert!(!proxy.state.instances.contains_key("peer-instance"));
    assert!(!proxy.state.apps.contains_key("peer-app"));
    assert!(!proxy
        .state
        .allocated_addresses
        .contains(&"10.0.0.40".parse().unwrap()));
}

/// Whether this node's ephemeral observations of `instance_id` are live.
fn observations_are_live(state: &TestState, instance_id: &str) -> (bool, bool) {
    let node = state.kv_store.my_node_id();
    let store = state.kv_store.ephemeral().read();
    let live = |key: String| store.get(&key).is_some_and(|entry| !entry.is_deleted());
    (
        live(crate::kv::keys::conn(instance_id, node)),
        live(crate::kv::keys::handshake(instance_id, node)),
    )
}

/// A delete can only withdraw the deleting node's own `conn/` and `handshake/`
/// keys -- those are the only ones it owns. Every other node has to withdraw
/// its own when it learns of the deletion, or its observation of a CVM that no
/// longer exists is never collected: nothing else iterates those prefixes, and
/// the recycle loop cannot see an instance it has already dropped from memory.
#[tokio::test]
async fn learning_of_a_remote_deletion_withdraws_this_nodes_observations() {
    let state = create_test_state().await;
    sync_from_peer(
        &state,
        "peer-instance",
        "10.0.0.40",
        &test_pubkey("peer-key"),
    );
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    // This node has been watching it, as every node in the cluster does.
    state.kv_store.sync_connections("peer-instance", 4).unwrap();
    state
        .kv_store
        .sync_instance_handshake("peer-instance", 1)
        .unwrap();
    assert_eq!(observations_are_live(&state, "peer-instance"), (true, true));

    // The tombstone arrives through sync: the peer withdrew its own keys, not
    // ours. Written directly rather than through `sync_delete_instance`, which
    // is what the *deleting* node calls.
    state
        .kv_store
        .persistent()
        .write()
        .delete(crate::kv::keys::inst("peer-instance"))
        .unwrap();
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    assert!(!state.lock().state.instances.contains_key("peer-instance"));
    assert_eq!(
        observations_are_live(&state, "peer-instance"),
        (false, false),
        "this node's observations must not outlive the instance they describe"
    );
}

#[tokio::test]
async fn proxy_state_adopts_the_wavekv_winner_regardless_of_value_reg_time() {
    let state = create_test_state().await;
    sync_from_peer_at(
        &state,
        "contended",
        "10.0.0.40",
        &test_pubkey("old-key"),
        300,
    );
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    state
        .lock()
        .state
        .instances
        .get("contended")
        .unwrap()
        .connections
        .store(7, Ordering::Relaxed);

    // This is the value WaveKV selected using its own entry metadata. Its
    // payload timestamp is older, so comparing reg_time again would leave the
    // data plane permanently materializing a losing value.
    sync_from_peer_at(
        &state,
        "contended",
        "10.0.0.41",
        &test_pubkey("winner-key"),
        100,
    );
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    let instance = &proxy.state.instances["contended"];
    assert_eq!(instance.ip, "10.0.0.41".parse::<Ipv4Addr>().unwrap());
    assert_eq!(instance.public_key, test_pubkey("winner-key"));
    assert_eq!(encode_ts(instance.reg_time), 100);
    assert_eq!(instance.num_connections(), 7);
    assert!(!proxy
        .state
        .allocated_addresses
        .contains(&"10.0.0.40".parse().unwrap()));
}

#[tokio::test]
async fn a_local_registration_survives_a_reload_that_cannot_see_it_yet() {
    let state = create_test_state().await;
    state
        .lock()
        .new_client_by_id("fresh", "fresh-app", &test_pubkey("fresh-key"), "", None)
        .unwrap();
    // Stand in for a KV write that failed: the instance exists locally only.
    // Evicting it would black-hole a live CVM until it re-registers.
    state
        .kv_store
        .persistent()
        .write()
        .delete(crate::kv::keys::inst("fresh"))
        .unwrap();

    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    assert!(state.lock().state.instances.contains_key("fresh"));
}

#[tokio::test]
async fn a_record_that_stops_validating_keeps_the_instance_it_describes() {
    let state = create_test_state().await;
    sync_from_peer(&state, "peer-instance", "10.0.0.40", &test_pubkey("good"));
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    assert!(state.lock().state.instances.contains_key("peer-instance"));

    // A peer overwrites the record with one this node refuses. "I cannot read
    // your current state" is not "you were deleted": the last known-good state
    // keeps the CVM reachable until a usable record or a real deletion arrives.
    sync_from_peer(&state, "peer-instance", "10.0.0.40", "not-a-key");
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    let instance = proxy
        .state
        .instances
        .get("peer-instance")
        .expect("a rejected record must not evict the instance");
    assert_eq!(instance.public_key, test_pubkey("good"));
    assert!(proxy.generate_wg_config().unwrap().contains("10.0.0.40"));
}

#[tokio::test]
async fn an_undecodable_record_keeps_the_instance_it_describes() {
    let state = create_test_state().await;
    sync_from_peer(&state, "peer-instance", "10.0.0.40", &test_pubkey("good"));
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    // A torn write, or a record written by a build whose schema this one cannot
    // read. Folding that into "absent" would let a rolling upgrade evict every
    // instance the newer nodes registered.
    state
        .kv_store
        .persistent()
        .write()
        .put(
            crate::kv::keys::inst("peer-instance"),
            b"not-messagepack".to_vec(),
        )
        .unwrap();
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    assert!(state.lock().state.instances.contains_key("peer-instance"));
}

#[tokio::test]
async fn an_operator_can_remove_a_cvm_whose_kv_record_is_unreadable() {
    let state = create_test_state().await;
    sync_from_peer(&state, "peer-instance", "10.0.0.40", &test_pubkey("good"));
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    state
        .kv_store
        .persistent()
        .write()
        .put(
            crate::kv::keys::inst("peer-instance"),
            b"not-messagepack".to_vec(),
        )
        .unwrap();

    let removal = state.proxy.remove_cvm("peer-instance").unwrap();
    assert!(removal.record_existed);
    assert!(removal.removed_locally);
    assert!(!state.lock().state.instances.contains_key("peer-instance"));
    let loaded = state.kv_store.load_all_instances();
    assert!(!loaded.decoded.contains_key("peer-instance"));
    assert!(!loaded.undecodable.contains_key("peer-instance"));

    // The recovery operation is safe to retry after a timeout or lost reply,
    // and the retry tells the operator there was nothing left to remove.
    let retry = state.proxy.remove_cvm("peer-instance").unwrap();
    assert!(!retry.record_existed);
    assert!(!retry.removed_locally);
}

#[tokio::test]
async fn removing_an_unknown_cvm_reports_that_nothing_existed() {
    let state = create_test_state().await;

    // A mistyped instance_id must not be mistaken for a successful removal.
    let removal = state.proxy.remove_cvm("no-such-instance").unwrap();
    assert!(!removal.record_existed);
    assert!(!removal.removed_locally);
}

#[tokio::test]
async fn rejected_instance_records_are_visible_to_the_operator() {
    let state = create_test_state().await;
    sync_from_peer(&state, "peer-instance", "10.0.0.40", &test_pubkey("good"));
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    assert!(state.proxy.rejected_instances().is_empty());

    state
        .kv_store
        .persistent()
        .write()
        .put(
            crate::kv::keys::inst("peer-instance"),
            b"not-messagepack".to_vec(),
        )
        .unwrap();

    // The operator can see what is wrong — with the actual decode error, and
    // whether removal would also drop live routing — without grepping logs.
    let rejected = state.proxy.rejected_instances();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].rejected.instance_id, "peer-instance");
    assert!(format!("{:#}", rejected[0].rejected.reason).contains("corrupt record"));
    assert!(rejected[0].active_locally);

    // Once removed, the record no longer shows up as rejected.
    state.proxy.remove_cvm("peer-instance").unwrap();
    assert!(state.proxy.rejected_instances().is_empty());
}

#[tokio::test]
async fn an_operator_can_remove_a_decommissioned_node() {
    let state = create_test_state().await;
    let kv = &state.kv_store;
    kv.register_peer_url(7, "https://gw7.example.com:9202")
        .unwrap();
    kv.sync_node(
        7,
        &crate::kv::NodeData {
            uuid: b"gw7-uuid".to_vec(),
            url: "https://gw7.example.com:9202".to_string(),
            wg_public_key: String::new(),
            wg_endpoint: String::new(),
            wg_ip: String::new(),
        },
    )
    .unwrap();

    let removal = state.proxy.remove_node(7).unwrap();
    assert!(removal.record_existed);
    assert!(removal.removed_from_peer_set);
    assert!(kv.get_peer_url(7).is_none());
    assert!(!kv.load_all_nodes().contains_key(&7));
    let peers = kv.persistent().read().status().peers;
    assert!(!peers.iter().any(|peer| peer.id == 7));

    // The recovery operation is safe to retry after a timeout or lost reply,
    // and the retry tells the operator there was nothing left to remove.
    let retry = state.proxy.remove_node(7).unwrap();
    assert!(!retry.record_existed);
    assert!(!retry.removed_from_peer_set);

    // A node known only by its sync address (registered via SetNodeUrl but
    // never booted) still reports record_existed.
    kv.register_peer_url(8, "https://gw8.example.com:9202")
        .unwrap();
    let removal = state.proxy.remove_node(8).unwrap();
    assert!(removal.record_existed);
}

#[tokio::test]
async fn a_node_cannot_remove_itself() {
    let state = create_test_state().await;
    let my_id = state.proxy.config.sync.node_id;
    assert!(state.proxy.remove_node(my_id).is_err());
}

#[tokio::test]
async fn peers_prune_nodes_removed_on_another_gateway() {
    let state = create_test_state().await;
    let kv = &state.kv_store;

    // Simulate observing a removal performed elsewhere: the __peer_addr
    // tombstone arrives via replication, not through this node's admin API.
    kv.register_peer_url(9, "https://gw9.example.com:9202")
        .unwrap();
    kv.persistent()
        .write()
        .delete(crate::kv::keys::peer_addr(9))
        .unwrap();
    kv.prune_removed_peers();
    let peers = kv.persistent().read().status().peers;
    assert!(!peers.iter().any(|peer| peer.id == 9));

    // A peer whose address record was never written is not dropped:
    // bootstrap can add a peer before its address has synced in.
    kv.add_peer(11).unwrap();
    kv.prune_removed_peers();
    let peers = kv.persistent().read().status().peers;
    assert!(peers.iter().any(|peer| peer.id == 11));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_node_reports_peer_membership_despite_a_racing_watcher() {
    let state = create_test_state().await;
    let kv = state.kv_store.clone();

    // The production watch task prunes the peer set as soon as the
    // __peer_addr tombstone lands. remove_node must capture membership
    // before publishing the tombstone, or the answer it returns would
    // depend on which of the two gets there first.
    let mut rx = kv.watch_peer_addrs();
    let kv_for_watch = kv.clone();
    let watcher = tokio::spawn(async move {
        while rx.changed().await.is_ok() {
            kv_for_watch.prune_removed_peers();
        }
    });

    for node_id in 100..120 {
        kv.register_peer_url(node_id, "https://gw.example.com:9202")
            .unwrap();
        let removal = state.proxy.remove_node(node_id).unwrap();
        assert!(removal.record_existed);
        assert!(
            removal.removed_from_peer_set,
            "node {node_id}: membership must be captured before the tombstone publishes"
        );
        let peers = kv.persistent().read().status().peers;
        assert!(!peers.iter().any(|peer| peer.id == node_id));
    }

    watcher.abort();
}

#[tokio::test]
async fn a_zt_domain_with_a_corrupt_config_can_still_be_deleted() {
    let state = create_test_state().await;
    let kv = &state.kv_store;

    kv.persistent()
        .write()
        .put(
            crate::kv::keys::zt_domain_config("bad.example.com"),
            b"not-messagepack".to_vec(),
        )
        .unwrap();

    // The corrupt record is invisible to reads, but must still be deletable —
    // otherwise it would be permanently stuck.
    assert!(kv.get_zt_domain_config("bad.example.com").is_none());
    assert!(kv.zt_domain_config_exists("bad.example.com"));

    kv.delete_zt_domain_config("bad.example.com").unwrap();
    assert!(!kv.zt_domain_config_exists("bad.example.com"));
}

#[tokio::test]
async fn an_instance_that_lost_an_ip_conflict_stops_being_routable() {
    let state = create_test_state().await;
    sync_from_peer_at(&state, "loser", "10.0.0.40", &test_pubkey("loser"), 300);
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    assert!(state.lock().state.instances.contains_key("loser"));

    // An older registration claims the same IP. Unlike an unreadable record,
    // this one is readable and says the address belongs to someone else, so
    // the loser has to go: two peers on one IP is a config `wg` will not load.
    sync_from_peer_at(&state, "winner", "10.0.0.40", &test_pubkey("winner"), 100);
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    assert!(!proxy.state.instances.contains_key("loser"));
    assert!(proxy.state.instances.contains_key("winner"));
}

#[tokio::test]
async fn a_future_dated_registration_cannot_park_itself_in_the_data_plane() {
    let state = create_test_state().await;
    // Both the removal pass and `recycle()` age instances with
    // `elapsed().unwrap_or_default()`, which reads a future `reg_time` as zero
    // age — an instance dated forward would survive deletion and recycling
    // alike until this process restarts.
    let far_future = now_secs() + 365 * 24 * 3600;
    sync_from_peer_at(&state, "zombie", "10.0.0.40", &test_pubkey("z"), far_future);
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    assert!(!state.lock().state.instances.contains_key("zombie"));
}

#[tokio::test]
async fn a_stuck_bad_record_is_reported_once_and_again_when_it_recovers() {
    let state = create_test_state().await;
    sync_from_peer(&state, "peer-instance", "10.0.0.40", "not-a-key");

    // A record is refused for what it contains, so it stays refused until
    // someone rewrites it. `reported_rejections` is what keeps the reload from
    // re-emitting the same `error!` on every round: a reason already in the map
    // is not logged again, so a second identical reload must leave it untouched.
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    let first = state.lock().reported_rejections.clone();
    assert_eq!(first.len(), 1);
    assert!(first["peer-instance"].contains("public key"));

    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    assert_eq!(state.lock().reported_rejections, first);

    // Recovery is a transition too, and clearing the entry is what lets a
    // later relapse be reported instead of silently swallowed.
    sync_from_peer(&state, "peer-instance", "10.0.0.40", &test_pubkey("good"));
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();
    assert!(state.lock().reported_rejections.is_empty());
}
