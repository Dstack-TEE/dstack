// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::{load_config_figment, Config, MutualConfig};
use crate::kv::PortFlags;
use crate::proxy::port_policy::is_port_allowed;
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

fn policy(restrict: bool, ports: &[u16]) -> PortPolicy {
    PortPolicy {
        ports: ports
            .iter()
            .map(|p| (*p, PortFlags { pp: false }))
            .collect(),
        restrict_mode: restrict,
    }
}

#[tokio::test]
async fn test_port_policy_restrict_mode_allows_listed_only() {
    let state = create_test_state().await;
    state
        .lock()
        .new_client_by_id(
            "inst-allow",
            "app-allow",
            "pubkey-allow",
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
            "pubkey-open",
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
            "pubkey-legacy",
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
            "pubkey-ovr",
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
            "pubkey-lock",
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
            "pubkey-revert",
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
            "pubkey-upgrade",
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
            "pubkey-upgrade",
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
        .new_client_by_id("test-id-0", "app-id-0", "test-pubkey-0", "", None)
        .unwrap();

    info.reg_time = SystemTime::UNIX_EPOCH;
    insta::assert_debug_snapshot!(info);
    let mut info1 = state
        .lock()
        .new_client_by_id("test-id-1", "app-id-1", "test-pubkey-1", "", None)
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
                    &format!("top-key-{index}"),
                    "",
                    Some(policy(false, &[])),
                )
                .unwrap();
        }
        proxy.handshake_cache.set_for_test(BTreeMap::from([
            ("top-key-0".to_string(), now),
            ("top-key-1".to_string(), now - 1),
            ("top-key-2".to_string(), now - 2),
            ("top-key-3".to_string(), now - 3600),
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
            ("top-key-0".to_string(), now - 3600),
            ("top-key-1".to_string(), now - 3600),
            ("top-key-2".to_string(), now - 3600),
            ("top-key-3".to_string(), now),
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
                "top-key-4",
                "",
                Some(policy(false, &[])),
            )
            .unwrap();
        assert!(proxy.state.top_n.is_empty());
        proxy.handshake_cache.set_for_test(BTreeMap::from([
            ("top-key-0".to_string(), now - 3600),
            ("top-key-1".to_string(), now - 3600),
            ("top-key-2".to_string(), now - 3600),
            ("top-key-3".to_string(), now),
            ("top-key-4".to_string(), now - 1),
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
