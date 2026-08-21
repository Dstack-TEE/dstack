// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::{load_config_figment, Config, MutualConfig};
use crate::kv::PortFlags;
use crate::proxy::port_policy::is_port_allowed;
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
    // Same reason: the default points at a real deployment path, and a stray
    // snapshot there would seed tests with verdicts they never observed.
    config.proxy.health_check.state_file = temp_dir
        .path()
        .join("instance-health.json")
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
    let result = state.do_register_cvm("app", "instance", "invalid", "compose", Default::default());

    assert!(result.is_err());
    assert!(!state.lock().state.instances.contains_key("instance"));
}

#[tokio::test]
async fn test_wireguard_public_key_cannot_be_reused_by_another_instance() {
    const PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let state = create_test_state().await;
    state
        .lock()
        .new_client_by_id(
            "instance-1",
            "app",
            PUBLIC_KEY,
            "compose",
            Default::default(),
        )
        .unwrap();

    let result = state.do_register_cvm(
        "app",
        "instance-2",
        PUBLIC_KEY,
        "compose",
        Default::default(),
    );

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
            Some(policy(true, &[8080, 9090])).into(),
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
            Some(policy(false, &[8080])).into(),
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
            Default::default(),
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
            Some(policy(true, &[8080])).into(),
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
            Some(policy(true, &[])).into(),
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
            Some(policy(true, &[8080])).into(),
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
            Some(policy(true, &[8080])).into(),
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
            Some(policy(true, &[7070, 8080])).into(),
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
            Default::default(),
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
            Default::default(),
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
                    Some(policy(false, &[])).into(),
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
                Some(policy(false, &[])).into(),
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
    register_instances(proxy, app, count, false);
}

/// Register `count` instances of `app` and mark every handshake fresh.
///
/// `health_check` mirrors what the CVM declares at registration: false is a
/// legacy image the gateway never polls, true is one that starts out `Unknown`
/// and has to be polled before it can serve.
fn register_instances(proxy: &mut ProxyState, app: &str, count: usize, health_check: bool) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut handshakes = BTreeMap::new();
    for index in 0..count {
        let id = format!("{app}-{index}");
        let key = test_pubkey(&format!("{app}-key-{index}"));
        proxy
            .new_client_by_id(
                &id,
                app,
                &key,
                "",
                ReportedCapabilities {
                    port_policy: Some(policy(false, &[])),
                    health_check: Some(health_check),
                },
            )
            .unwrap();
        handshakes.insert(key, now);
    }
    proxy.handshake_cache.set_for_test(handshakes);
}

/// Feed the poller's verdict in directly, standing in for a round of RPCs.
///
/// Builds the target from the instance's current record, i.e. the case where
/// nothing changed under the poller. `observe_from` covers the case where
/// something did.
fn observe(proxy: &mut ProxyState, instance_id: &str, state: HealthState) {
    let info = proxy.state.instances[instance_id].clone();
    observe_from(
        proxy,
        &crate::proxy::health_check::Target {
            id: info.id,
            ip: info.ip,
            public_key: info.public_key,
        },
        state,
    );
}

/// Feed a verdict in against a specific target, so a stale one can be tested.
fn observe_from(
    proxy: &mut ProxyState,
    target: &crate::proxy::health_check::Target,
    state: HealthState,
) -> bool {
    proxy.record_instance_health(
        target,
        crate::proxy::health_check::Observation {
            state,
            reason: String::new(),
        },
    )
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
            Some(policy(false, &[])).into(),
        )
        .unwrap();

    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("reboot-app").unwrap()),
        vec!["reboot-app-1"],
        "a rebooted instance must stay out of rotation until an operator says otherwise"
    );
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

    // A peer gated peer-app-0 and the record reached us through sync.
    let gated = {
        let proxy = state.lock();
        let existing = proxy.state.instances["peer-app-0"].clone();
        InstanceData {
            app_id: existing.app_id.clone(),
            ip: existing.ip,
            public_key: existing.public_key.clone(),
            reg_time: now,
            port_policy: existing.port_policy.clone(),
            port_policy_hash: existing.port_policy_hash.clone(),
            admin_port_policy: None,
            ready: Some(false),
            health_check: Some(existing.health_check),
        }
    };
    state.kv_store.sync_instance("peer-app-0", &gated).unwrap();
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

/// The reload resets health when the declared capability changes, which flips
/// eligibility. That has to drop the cached selection for the same reason a
/// gate arriving through KV does, or the stale `top_n` keeps routing to an
/// instance the reload just took out of the running.
#[tokio::test]
async fn a_capability_change_arriving_through_kv_invalidates_the_cached_selection() {
    let state = create_test_state().await;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut proxy = state.lock();
        // Neither opted in, so both read as `Ungated`: both are eligible and
        // the selection caches them.
        register_instances(&mut proxy, "swap-app", 2, false);
        proxy.select_top_n_hosts("swap-app").unwrap();
        assert_eq!(proxy.state.top_n.len(), 1, "selection should be cached");
    }

    // The instance came back on an image whose app does ask to be gated, and
    // the record reached us through sync. It starts `Unknown` until a poll
    // answers, so it is no longer eligible.
    let upgraded = {
        let proxy = state.lock();
        let existing = proxy.state.instances["swap-app-0"].clone();
        InstanceData {
            app_id: existing.app_id.clone(),
            ip: existing.ip,
            public_key: existing.public_key.clone(),
            reg_time: now,
            port_policy: existing.port_policy.clone(),
            port_policy_hash: existing.port_policy_hash.clone(),
            admin_port_policy: None,
            ready: existing.ready,
            health_check: Some(true),
        }
    };
    state
        .kv_store
        .sync_instance("swap-app-0", &upgraded)
        .unwrap();
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let mut proxy = state.lock();
    assert_eq!(
        proxy.state.instances["swap-app-0"].health,
        HealthState::Unknown
    );
    assert!(
        proxy.state.top_n.is_empty(),
        "a capability change arriving through KV must drop the cached selection"
    );
    proxy.handshake_cache.set_for_test(BTreeMap::from([
        (test_pubkey("swap-app-key-0"), now),
        (test_pubkey("swap-app-key-1"), now),
    ]));
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("swap-app").unwrap()),
        vec!["swap-app-1"]
    );
}

/// Whether this node's `conn/` record for the fixture instance is live.
///
/// Reads the raw entry because `KvStore` exposes no conn accessor, and uses the
/// store's own node id rather than the config's so the key matches whatever
/// `sync_connections` wrote -- the two agree today, and this keeps the
/// assertions honest if they ever stop agreeing.
fn conn_is_live(state: &TestState) -> bool {
    let key = crate::kv::keys::conn("gone-app-0", state.kv_store.my_node_id());
    state
        .kv_store
        .ephemeral()
        .read()
        .get(&key)
        .is_some_and(|entry| !entry.is_deleted())
}

/// Whether this node's `handshake/` observation for the fixture instance is live.
fn handshake_is_live(state: &TestState) -> bool {
    state
        .kv_store
        .get_instance_handshakes("gone-app-0")
        .contains_key(&state.kv_store.my_node_id())
}

/// Removing an instance must take its gate with it, or a later instance
/// reusing the id would inherit a quarantine nobody asked for.
#[tokio::test]
async fn removing_an_instance_removes_its_gate() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_ready_instances(&mut proxy, "gone-app", 2);
        proxy.set_ready("gone-app-0", false).unwrap();
        assert_eq!(
            state.kv_store.load_all_instances().decoded["gone-app-0"].ready,
            Some(false)
        );
        // Seed the two ephemeral records as well, or the assertions below pass
        // whether or not the deletes are issued.
        state.kv_store.sync_connections("gone-app-0", 3).unwrap();
        state
            .kv_store
            .sync_instance_handshake("gone-app-0", 1)
            .unwrap();
        // Assert they are live first. Without this the post-delete assertions
        // go quietly vacuous again the moment the seeds stop landing on the
        // keys they are checked against -- which is the failure this test
        // exists to rule out.
        assert!(conn_is_live(&state), "seeded conn/ record should be live");
        assert!(
            handshake_is_live(&state),
            "seeded handshake/ record should be live"
        );
        proxy.remove_instance("gone-app-0").unwrap();
    }
    // The gate lives in the instance record, so removing the instance takes it
    // with it. The deletes are issued unconditionally so a failure in one
    // cannot strand the others, which is only worth anything if they are all
    // actually issued.
    let key = crate::kv::keys::inst("gone-app-0");
    let live = state
        .kv_store
        .persistent()
        .read()
        .get(&key)
        .is_some_and(|entry| !entry.is_deleted());
    assert!(!live, "{key} should be gone");
    assert!(
        !handshake_is_live(&state),
        "handshake/ record should be gone"
    );
    assert!(!conn_is_live(&state), "conn/ record should be gone");
}

/// Selection handing over an empty group means every instance was ruled out
/// before the port policy ever looked -- an operator drained the app, or none
/// passed the handshake filter. Blaming the port policy sends whoever reads the
/// log at the wrong subsystem.
#[tokio::test]
async fn an_empty_candidate_group_is_not_blamed_on_the_port_policy() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_ready_instances(&mut proxy, "drain-all", 1);
        proxy.set_ready("drain-all-0", false).unwrap();
    }
    let mut proxy = state.lock();
    let empty = proxy.select_top_n_hosts("drain-all").unwrap();
    assert!(empty.is_empty());
    drop(proxy);

    let err =
        crate::proxy::port_policy::filter_allowed_addresses(&state.proxy, empty, "drain-all", 443)
            .unwrap_err()
            .to_string();
    assert!(
        err.contains("no instance") && !err.contains("port policy"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn gating_an_unregistered_instance_is_an_error() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    assert!(proxy.set_ready("never-registered", false).is_err());
}

/// The bug this whole mechanism exists for: an instance registers during boot,
/// before its containers are up, and is immediately eligible for traffic.
#[tokio::test]
async fn a_newly_registered_instance_waits_for_its_first_health_poll() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "boot-app", 2, true);
    observe(&mut proxy, "boot-app-0", HealthState::Healthy);

    // boot-app-1 has registered but not yet answered a poll, so it is not
    // serving traffic on the strength of having finished a WireGuard handshake.
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("boot-app").unwrap()),
        vec!["boot-app-0"]
    );

    observe(&mut proxy, "boot-app-1", HealthState::Healthy);
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("boot-app").unwrap()).len(),
        2
    );
}

/// An image with no `Worker.Health` is never polled and must keep serving, or
/// upgrading a fleet one instance at a time would drain the un-upgraded half.
#[tokio::test]
async fn an_agent_that_cannot_report_health_stays_eligible() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "legacy-app", 2, false);

    for index in 0..2 {
        let id = format!("legacy-app-{index}");
        assert_eq!(
            proxy.state.instances[&id].health,
            HealthState::Ungated,
            "an agent that never declared the capability must not sit in Unknown"
        );
    }
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("legacy-app").unwrap()).len(),
        2
    );
}

#[tokio::test]
async fn an_unhealthy_instance_drops_out_of_rotation() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "sick-app", 3, true);
    for index in 0..3 {
        observe(
            &mut proxy,
            &format!("sick-app-{index}"),
            HealthState::Healthy,
        );
    }
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("sick-app").unwrap()).len(),
        3
    );

    observe(&mut proxy, "sick-app-1", HealthState::Unhealthy);
    let after = selected_ids(&proxy.select_top_n_hosts("sick-app").unwrap());
    assert_eq!(after, vec!["sick-app-0", "sick-app-2"]);
}

/// Health is a guess. A probe misconfigured across a whole app, or an agent
/// bug that lands everywhere at once, must not take the app offline.
#[tokio::test]
async fn an_app_with_no_healthy_instance_fails_open() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "open-app", 2, true);
    observe(&mut proxy, "open-app-0", HealthState::Unhealthy);
    observe(&mut proxy, "open-app-1", HealthState::Unhealthy);

    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("open-app").unwrap()).len(),
        2,
        "every instance unhealthy should route to all of them, not to none"
    );
}

/// Fail-open applies to health only. The operator gate is an instruction and
/// still wins, even when the surviving instance is perfectly healthy.
#[tokio::test]
async fn failing_open_on_health_does_not_reopen_the_operator_gate() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "mixed-app", 2, true);
    observe(&mut proxy, "mixed-app-0", HealthState::Unhealthy);
    observe(&mut proxy, "mixed-app-1", HealthState::Unhealthy);
    proxy.set_ready("mixed-app-0", false).unwrap();

    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("mixed-app").unwrap()),
        vec!["mixed-app-1"],
        "the gated instance must stay out even when health fails open"
    );
}

/// A health change has to beat the `cache_top_n` window, same as the gate.
#[tokio::test]
async fn a_health_change_invalidates_the_selection_cache() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "cached-app", 2, true);
    observe(&mut proxy, "cached-app-0", HealthState::Healthy);
    observe(&mut proxy, "cached-app-1", HealthState::Healthy);

    proxy.select_top_n_hosts("cached-app").unwrap();
    assert_eq!(proxy.state.top_n.len(), 1);

    observe(&mut proxy, "cached-app-0", HealthState::Unhealthy);
    assert!(proxy.state.top_n.is_empty());
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("cached-app").unwrap()),
        vec!["cached-app-1"]
    );
}

/// Same rule as the operator gate: an unhealthy instance is exactly the one an
/// operator needs to open a connection to.
#[tokio::test]
async fn an_unhealthy_instance_is_still_reachable_by_instance_id() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "direct-app", 2, true);
    observe(&mut proxy, "direct-app-0", HealthState::Healthy);
    observe(&mut proxy, "direct-app-1", HealthState::Unhealthy);

    let direct = proxy.select_top_n_hosts("direct-app-1").unwrap();
    assert_eq!(selected_ids(&direct), vec!["direct-app-1"]);
}

/// Re-register one instance the way a CVM does, with the key it presents.
fn re_register(
    proxy: &mut ProxyState,
    instance_id: &str,
    app: &str,
    public_key: &str,
    health_check: bool,
) {
    proxy
        .new_client_by_id(
            instance_id,
            app,
            public_key,
            "",
            ReportedCapabilities {
                port_policy: Some(policy(false, &[])),
                health_check: Some(health_check),
            },
        )
        .unwrap();
}

/// A boot regenerates the CVM's WireGuard key -- its key store is cached in
/// `/run`, which is tmpfs -- so a changed key is how a restart is told apart
/// from a refresh. The old verdict describes a process that no longer exists.
#[tokio::test]
async fn a_reboot_resets_health_to_unknown() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "restart-app", 2, true);
    observe(&mut proxy, "restart-app-0", HealthState::Healthy);
    observe(&mut proxy, "restart-app-1", HealthState::Healthy);

    let rebooted_key = test_pubkey("restart-app-key-0-second-boot");
    re_register(
        &mut proxy,
        "restart-app-0",
        "restart-app",
        &rebooted_key,
        true,
    );
    // The tunnel is rebuilt under the new key, so keep both handshakes fresh:
    // this test is about health, not about handshake staleness.
    proxy.handshake_cache.set_for_test(BTreeMap::from([
        (rebooted_key, now_secs()),
        (test_pubkey("restart-app-key-1"), now_secs()),
    ]));

    assert_eq!(
        proxy.state.instances["restart-app-0"].health,
        HealthState::Unknown
    );
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("restart-app").unwrap()),
        vec!["restart-app-1"]
    );
}

/// Registration is not boot-only: the gateway-checker re-registers every 180s
/// and whenever the handshake goes stale, reusing the key cached in `/run`.
/// Resetting on those would take a healthy instance out of the rotation every
/// three minutes for no reason.
#[tokio::test]
async fn a_periodic_re_registration_keeps_the_last_health_verdict() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "refresh-app", 2, true);
    observe(&mut proxy, "refresh-app-0", HealthState::Healthy);
    observe(&mut proxy, "refresh-app-1", HealthState::Healthy);

    re_register(
        &mut proxy,
        "refresh-app-0",
        "refresh-app",
        &test_pubkey("refresh-app-key-0"),
        true,
    );

    assert_eq!(
        proxy.state.instances["refresh-app-0"].health,
        HealthState::Healthy
    );
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("refresh-app").unwrap()),
        vec!["refresh-app-0", "refresh-app-1"]
    );
}

/// `record_instance_health`'s return value is the only thing that makes the
/// poller write the snapshot, so a mutation to it silently disables restart
/// survival with every other test still green.
#[tokio::test]
async fn recording_reports_whether_anything_changed() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "changed-app", 1, true);
    let info = proxy.state.instances["changed-app-0"].clone();
    let target = crate::proxy::health_check::Target {
        id: info.id.clone(),
        ip: info.ip,
        public_key: info.public_key.clone(),
    };

    assert!(
        observe_from(&mut proxy, &target, HealthState::Healthy),
        "a new verdict is a change"
    );
    assert!(
        !observe_from(&mut proxy, &target, HealthState::Healthy),
        "the same verdict again is not"
    );
    assert!(
        observe_from(&mut proxy, &target, HealthState::Unhealthy),
        "a different verdict is"
    );
}

/// A peer on a build predating the capability field rewrites `inst/` without
/// it. Across a process restart there is no in-memory record to inherit from,
/// so reading that as "opted out" would switch off a gate the app paid for
/// until the CVM re-registers. The snapshot is the second witness.
#[tokio::test]
async fn a_restart_does_not_ungate_an_instance_an_older_peer_rewrote() {
    let state = create_test_state().await;
    let path = state.config.proxy.health_check.state_file.clone();
    let rewritten = {
        let mut proxy = state.lock();
        register_instances(&mut proxy, "restart-mixed-app", 1, true);
        observe(&mut proxy, "restart-mixed-app-0", HealthState::Healthy);
        let existing = proxy.state.instances["restart-mixed-app-0"].clone();
        InstanceData {
            app_id: existing.app_id.clone(),
            ip: existing.ip,
            public_key: existing.public_key.clone(),
            reg_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            port_policy: existing.port_policy.clone(),
            port_policy_hash: existing.port_policy_hash.clone(),
            admin_port_policy: None,
            ready: existing.ready,
            // The older peer does not know the field exists.
            health_check: None,
        }
    };
    crate::proxy::health_check::save_snapshot(&state.proxy);
    state
        .kv_store
        .sync_instance("restart-mixed-app-0", &rewritten)
        .unwrap();

    // What a restarted process does.
    let store = crate::proxy::health_store::HealthStore::load(&path);
    let rebuilt =
        build_state_from_kv_store(&state.config, state.kv_store.load_all_instances(), &store);

    assert!(
        rebuilt.instances["restart-mixed-app-0"].health_check,
        "a restart must not read an older peer's rewrite as an opt-out"
    );
    assert_eq!(
        rebuilt.instances["restart-mixed-app-0"].health,
        HealthState::Healthy
    );
}

/// The snapshot module is unit-tested on its own, but nothing verified that the
/// gateway actually writes to it and reads from it. Deleting either side left
/// the whole suite green, so a feature that is inert in production would have
/// looked fine here.
#[tokio::test]
async fn a_verdict_survives_rebuilding_state_from_the_store() {
    let state = create_test_state().await;
    let path = state.config.proxy.health_check.state_file.clone();
    {
        let mut proxy = state.lock();
        register_instances(&mut proxy, "persist-app", 2, true);
        observe(&mut proxy, "persist-app-0", HealthState::Healthy);
        observe(&mut proxy, "persist-app-1", HealthState::Unhealthy);
    }
    crate::proxy::health_check::save_snapshot(&state.proxy);

    // What a restarted process does: read the snapshot, then rebuild every
    // instance from the store.
    let store = crate::proxy::health_store::HealthStore::load(&path);
    let rebuilt =
        build_state_from_kv_store(&state.config, state.kv_store.load_all_instances(), &store);

    assert_eq!(
        rebuilt.instances["persist-app-0"].health,
        HealthState::Healthy,
        "a restart re-derived a verdict it had already observed"
    );
    assert_eq!(
        rebuilt.instances["persist-app-1"].health,
        HealthState::Unhealthy
    );
}

/// The reboot reset is applied by whichever node took the re-registration.
/// Every other node learns about the new boot through sync, and must not carry
/// its own pre-reboot verdict across -- otherwise the guard in
/// `record_instance_health` closes a two-second window while this leaves a
/// whole-poll-interval one open on every peer.
#[tokio::test]
async fn a_reboot_arriving_through_kv_resets_health_on_this_node_too() {
    let state = create_test_state().await;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut proxy = state.lock();
        register_instances(&mut proxy, "peer-reboot-app", 1, true);
        observe(&mut proxy, "peer-reboot-app-0", HealthState::Healthy);
    }

    // The CVM rebooted and re-registered somewhere else, so it comes back with
    // a fresh WireGuard key. Everything else about the record is unchanged.
    let rebooted = {
        let proxy = state.lock();
        let existing = proxy.state.instances["peer-reboot-app-0"].clone();
        InstanceData {
            app_id: existing.app_id.clone(),
            ip: existing.ip,
            public_key: test_pubkey("peer-reboot-app-key-0-second-boot"),
            reg_time: now,
            port_policy: existing.port_policy.clone(),
            port_policy_hash: existing.port_policy_hash.clone(),
            admin_port_policy: None,
            ready: existing.ready,
            health_check: Some(true),
        }
    };
    state
        .kv_store
        .sync_instance("peer-reboot-app-0", &rebooted)
        .unwrap();
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    assert_eq!(
        proxy.state.instances["peer-reboot-app-0"].health,
        HealthState::Unknown,
        "the pre-reboot verdict was carried onto the new boot"
    );
}

/// A node running a build that predates the capability field rewrites `inst/`
/// records without it -- it does that on every re-registration it handles. That
/// record says nothing about the app's intent, so reading it as "opted out"
/// would reset health, drop the app's cached selection, and flap the instance
/// back on the next sync round, for as long as the cluster is mixed.
#[tokio::test]
async fn a_record_from_an_older_peer_does_not_clear_the_capability() {
    let state = create_test_state().await;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut proxy = state.lock();
        register_instances(&mut proxy, "mixed-app", 1, true);
        observe(&mut proxy, "mixed-app-0", HealthState::Healthy);
    }

    let rewritten = {
        let proxy = state.lock();
        let existing = proxy.state.instances["mixed-app-0"].clone();
        InstanceData {
            app_id: existing.app_id.clone(),
            ip: existing.ip,
            public_key: existing.public_key.clone(),
            reg_time: now,
            port_policy: existing.port_policy.clone(),
            port_policy_hash: existing.port_policy_hash.clone(),
            admin_port_policy: None,
            ready: existing.ready,
            // The older peer does not know the field exists.
            health_check: None,
        }
    };
    state
        .kv_store
        .sync_instance("mixed-app-0", &rewritten)
        .unwrap();
    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let proxy = state.lock();
    assert!(
        proxy.state.instances["mixed-app-0"].health_check,
        "an absent field must not read as an opt-out"
    );
    assert_eq!(
        proxy.state.instances["mixed-app-0"].health,
        HealthState::Healthy,
        "and must not reset the verdict this node observed"
    );
}

/// A CVM that is powered off sits in `state.instances` for up to
/// `recycle.timeout` -- ten hours by default -- while already being excluded
/// from routing by handshake age. Polling it every round would spend a full
/// timeout slot on a machine that is gone, and enough of them stretch the round
/// past the interval and slow detection down for every live instance.
#[tokio::test]
async fn an_instance_whose_handshake_went_stale_is_not_polled() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_instances(&mut proxy, "stale-app", 2, true);
        let stale = now_secs() - proxy.config.proxy.timeouts.handshake_stale.as_secs() - 60;
        proxy.handshake_cache.set_for_test(BTreeMap::from([
            (test_pubkey("stale-app-key-0"), now_secs()),
            (test_pubkey("stale-app-key-1"), stale),
        ]));
    }

    let targets = crate::proxy::health_check::select_targets(&state.proxy);
    let ids = targets.iter().map(|t| t.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids, vec!["stale-app-0"]);
}

/// A CVM that just registered has not completed a handshake yet. Absent is not
/// the same as stale, and reading it that way would mean an instance is never
/// polled until it has already carried traffic.
#[tokio::test]
async fn an_instance_with_no_handshake_yet_is_still_polled() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_instances(&mut proxy, "fresh-app", 1, true);
        proxy.handshake_cache.set_for_test(BTreeMap::new());
    }

    let targets = crate::proxy::health_check::select_targets(&state.proxy);
    assert_eq!(
        targets.len(),
        1,
        "a CVM with no handshake yet must be polled"
    );
}

/// An app that never opted in cannot be gated on the answer, so asking would
/// only produce failures to misread.
#[tokio::test]
async fn an_app_that_did_not_opt_in_is_not_polled() {
    let state = create_test_state().await;
    {
        let mut proxy = state.lock();
        register_instances(&mut proxy, "opt-out-app", 2, false);
    }

    assert!(crate::proxy::health_check::select_targets(&state.proxy).is_empty());
}

/// A round takes as long as its slowest instance, and a CVM can reboot inside
/// that window. The verdict polled from the previous boot must not land on the
/// new one -- it would let an instance whose containers are not up serve
/// immediately, which is the whole thing `Unknown` exists to prevent.
#[tokio::test]
async fn a_verdict_polled_before_a_reboot_is_not_applied_after_it() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "race-app", 1, true);

    // What the poller snapshotted at the start of the round.
    let polled = crate::proxy::health_check::Target {
        id: "race-app-0".to_string(),
        ip: proxy.state.instances["race-app-0"].ip,
        public_key: proxy.state.instances["race-app-0"].public_key.clone(),
    };

    // The CVM reboots and re-registers mid-round.
    let rebooted_key = test_pubkey("race-app-key-0-second-boot");
    re_register(&mut proxy, "race-app-0", "race-app", &rebooted_key, true);
    assert_eq!(
        proxy.state.instances["race-app-0"].health,
        HealthState::Unknown
    );

    // The in-flight poll finally lands.
    let applied = observe_from(&mut proxy, &polled, HealthState::Healthy);

    assert!(!applied, "a stale observation must not count as a change");
    assert_eq!(
        proxy.state.instances["race-app-0"].health,
        HealthState::Unknown,
        "the previous boot's verdict was applied to the new one"
    );
}

/// The IP can be reallocated to a different instance entirely, so it is checked
/// for the same reason the key is.
#[tokio::test]
async fn a_verdict_polled_from_a_stale_address_is_not_applied() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "addr-app", 1, true);

    let polled = crate::proxy::health_check::Target {
        id: "addr-app-0".to_string(),
        ip: "10.99.99.99".parse().unwrap(),
        public_key: proxy.state.instances["addr-app-0"].public_key.clone(),
    };

    assert!(!observe_from(&mut proxy, &polled, HealthState::Healthy));
    assert_eq!(
        proxy.state.instances["addr-app-0"].health,
        HealthState::Unknown
    );
}

/// The debug registration path has no CVM to ask, so it reports nothing about
/// the capability. It must not be able to take a real instance out of polling
/// for good by re-registering its id.
#[tokio::test]
async fn a_registration_that_reports_no_capability_leaves_it_alone() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "debug-app", 1, true);
    observe(&mut proxy, "debug-app-0", HealthState::Healthy);

    proxy
        .new_client_by_id(
            "debug-app-0",
            "debug-app",
            &test_pubkey("debug-app-key-0"),
            "",
            ReportedCapabilities {
                port_policy: Some(policy(false, &[])),
                health_check: None,
            },
        )
        .unwrap();

    assert!(
        proxy.state.instances["debug-app-0"].health_check,
        "a caller with nothing to say must not clear the declaration"
    );
    assert_eq!(
        proxy.state.instances["debug-app-0"].health,
        HealthState::Healthy,
        "and must not reset the verdict either"
    );
}

/// A different capability means a different image, so the verdict belongs to
/// something that is no longer running even if the key survived.
#[tokio::test]
async fn a_changed_health_capability_resets_health() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "swap-app", 1, true);
    observe(&mut proxy, "swap-app-0", HealthState::Healthy);

    re_register(
        &mut proxy,
        "swap-app-0",
        "swap-app",
        &test_pubkey("swap-app-key-0"),
        false,
    );

    assert_eq!(
        proxy.state.instances["swap-app-0"].health,
        HealthState::Ungated
    );
}

/// Turning polling off must restore the old behaviour exactly. Nothing ever
/// leaves `Unknown` once the poller is not running, and in a fleet that also
/// has apps which never opted in -- `Ungated`, which counts as healthy -- the
/// filter would otherwise drop every opted-in instance, forever.
#[tokio::test]
async fn disabling_polling_keeps_both_old_and_new_instances_eligible() {
    let state = create_test_state_with(|config| config.proxy.health_check.enabled = false).await;
    let mut proxy = state.lock();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // One legacy instance and one that declares the endpoint but, with the
    // poller off, will never answer.
    let mut handshakes = BTreeMap::new();
    for (index, has_endpoint) in [false, true].into_iter().enumerate() {
        let id = format!("off-app-{index}");
        let key = test_pubkey(&format!("off-app-key-{index}"));
        proxy
            .new_client_by_id(
                &id,
                "off-app",
                &key,
                "",
                ReportedCapabilities {
                    port_policy: Some(policy(false, &[])),
                    health_check: Some(has_endpoint),
                },
            )
            .unwrap();
        handshakes.insert(key, now);
    }
    proxy.handshake_cache.set_for_test(handshakes);

    assert_eq!(
        proxy.state.instances["off-app-1"].health,
        HealthState::Unknown,
        "the state is still tracked; it just must not be allowed to gate"
    );
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("off-app").unwrap()).len(),
        2,
        "with polling disabled every instance stays eligible"
    );
}

/// Health is this node's own observation and WaveKV does not carry it. A sync
/// round must not reset it, or the whole fleet drops to `Unknown` every time a
/// peer writes anything.
#[tokio::test]
async fn a_kv_reload_does_not_reset_this_node_s_health_observations() {
    let state = create_test_state().await;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut proxy = state.lock();
        register_instances(&mut proxy, "sync-app", 2, true);
        observe(&mut proxy, "sync-app-0", HealthState::Healthy);
        observe(&mut proxy, "sync-app-1", HealthState::Unhealthy);
    }

    reload_instances_from_kv_store(&state.proxy, &state.kv_store).unwrap();

    let mut proxy = state.lock();
    assert_eq!(
        proxy.state.instances["sync-app-0"].health,
        HealthState::Healthy
    );
    assert_eq!(
        proxy.state.instances["sync-app-1"].health,
        HealthState::Unhealthy
    );
    proxy.handshake_cache.set_for_test(BTreeMap::from([
        (test_pubkey("sync-app-key-0"), now),
        (test_pubkey("sync-app-key-1"), now),
    ]));
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("sync-app").unwrap()),
        vec!["sync-app-0"]
    );
}

/// The two selection paths express the "polling off means no gating" rule
/// through different mechanisms -- the top-n path folds it into the candidate
/// flag, the random path checks it inside `instance_is_healthy` -- so a
/// refactor could easily fix one and miss the other. This pins the combination
/// the other disabled-polling test does not reach.
///
/// The fleet is deliberately mixed. With two `Unknown` instances the fail-open
/// branch keeps both regardless, so the switch is never reached and the test
/// passes whether or not the code under test still exists -- which is exactly
/// what it did before, verified by deleting the check in `instance_is_healthy`
/// and watching every test still pass. One healthy peer makes `any_healthy`
/// true and forces the filter to actually run.
#[tokio::test]
async fn disabling_polling_also_keeps_the_random_path_open() {
    let state = create_test_state_with(|config| {
        config.proxy.health_check.enabled = false;
        config.proxy.connect_top_n = 0;
    })
    .await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "off-rand-app", 2, true);
    observe(&mut proxy, "off-rand-app-0", HealthState::Healthy);

    // One is healthy and one is `Unknown`, so with polling on the `Unknown` one
    // would be filtered out rather than saved by fail-open. With polling off
    // both must stay selectable.
    assert_eq!(
        proxy.state.instances["off-rand-app-0"].health,
        HealthState::Healthy
    );
    assert_eq!(
        proxy.state.instances["off-rand-app-1"].health,
        HealthState::Unknown
    );

    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..32 {
        let picked = selected_ids(&proxy.select_top_n_hosts("off-rand-app").unwrap());
        assert_eq!(picked.len(), 1, "the random path returns a single host");
        seen.insert(picked[0].clone());
    }
    assert_eq!(
        seen.len(),
        2,
        "both instances must remain reachable, got {seen:?}"
    );
}

/// `connect_top_n = 0` takes the random path, which filters separately.
#[tokio::test]
async fn the_random_selection_path_honours_health_and_fails_open() {
    let state = create_test_state_with(|config| config.proxy.connect_top_n = 0).await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "rand-app", 2, true);
    observe(&mut proxy, "rand-app-0", HealthState::Unhealthy);
    observe(&mut proxy, "rand-app-1", HealthState::Healthy);

    for _ in 0..16 {
        assert_eq!(
            selected_ids(&proxy.select_top_n_hosts("rand-app").unwrap()),
            vec!["rand-app-1"]
        );
    }

    // With nothing healthy left, the random path must fail open too.
    observe(&mut proxy, "rand-app-1", HealthState::Unhealthy);
    for _ in 0..16 {
        assert_eq!(
            proxy.select_top_n_hosts("rand-app").unwrap().len(),
            1,
            "fail-open should still yield a host on the random path"
        );
    }
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
                admin_port_policy: None,
                ready: None,
                health_check: Some(false),
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
        .new_client_by_id(
            "fresh",
            "fresh-app",
            &test_pubkey("fresh-key"),
            "",
            Default::default(),
        )
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
