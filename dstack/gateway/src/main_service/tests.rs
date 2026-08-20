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
/// `has_health_endpoint` mirrors what the CVM declares at registration: false is a
/// legacy image the gateway never polls, true is one that starts out `Unknown`
/// and has to be polled before it can serve.
fn register_instances(proxy: &mut ProxyState, app: &str, count: usize, has_health_endpoint: bool) {
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
                    has_health_endpoint,
                },
            )
            .unwrap();
        handshakes.insert(key, now);
    }
    proxy.handshake_cache.set_for_test(handshakes);
}

/// Feed the poller's verdict in directly, standing in for a round of RPCs.
fn observe(proxy: &mut ProxyState, instance_id: &str, state: HealthState) {
    proxy.record_instance_health(
        instance_id,
        crate::proxy::health_check::Observation {
            state,
            reason: String::new(),
        },
    );
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

    proxy.set_admin_ready("gated-app-1", false).unwrap();

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

    proxy.set_admin_ready("cache-app-0", false).unwrap();
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

    proxy.set_admin_ready("drained-app-0", false).unwrap();
    proxy.set_admin_ready("drained-app-1", false).unwrap();

    assert!(
        proxy.select_top_n_hosts("drained-app").unwrap().is_empty(),
        "an operator draining every instance must be obeyed, not overridden"
    );

    proxy.set_admin_ready("drained-app-1", true).unwrap();
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
    proxy.set_admin_ready("reboot-app-0", false).unwrap();

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
    proxy.set_admin_ready("random-app-0", false).unwrap();

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
            admin_ready: Some(false),
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

#[tokio::test]
async fn gating_an_unregistered_instance_is_an_error() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    assert!(proxy.set_admin_ready("never-registered", false).is_err());
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
            HealthState::Unsupported,
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
    proxy.set_admin_ready("mixed-app-0", false).unwrap();

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

/// Registration only runs at boot, so seeing it again means the CVM restarted
/// and the last verdict describes a process that no longer exists.
#[tokio::test]
async fn re_registration_resets_health_to_unknown() {
    let state = create_test_state().await;
    let mut proxy = state.lock();
    register_instances(&mut proxy, "restart-app", 2, true);
    observe(&mut proxy, "restart-app-0", HealthState::Healthy);
    observe(&mut proxy, "restart-app-1", HealthState::Healthy);

    proxy
        .new_client_by_id(
            "restart-app-0",
            "restart-app",
            &test_pubkey("restart-app-key-0"),
            "",
            ReportedCapabilities {
                port_policy: Some(policy(false, &[])),
                has_health_endpoint: true,
            },
        )
        .unwrap();

    assert_eq!(
        proxy.state.instances["restart-app-0"].health,
        HealthState::Unknown
    );
    assert_eq!(
        selected_ids(&proxy.select_top_n_hosts("restart-app").unwrap()),
        vec!["restart-app-1"]
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
                admin_ready: None,
                has_health_endpoint: false,
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
