// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::{load_config_figment, Config, MutualConfig};
use crate::kv::PortFlags;
use crate::proxy::port_policy::is_port_allowed;
use base64::Engine as _;
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

/// Write a record straight into the KV store, bypassing registration, the way
/// a peer's sync round would.
fn sync_from_peer(state: &TestState, instance_id: &str, ip: &str, public_key: &str) {
    state
        .kv_store
        .sync_instance(
            instance_id,
            &InstanceData {
                app_id: "peer-app".to_string(),
                ip: ip.parse().unwrap(),
                public_key: public_key.to_string(),
                reg_time: 1,
                port_policy: None,
                port_policy_hash: String::new(),
                admin_port_policy: None,
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
