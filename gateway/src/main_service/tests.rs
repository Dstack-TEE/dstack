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
