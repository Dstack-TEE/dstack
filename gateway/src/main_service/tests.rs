// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::{load_config_figment, Config};

async fn create_test_state() -> Proxy {
    let figment = load_config_figment(None);
    let mut config = figment.focus("core").extract::<Config>().unwrap();
    let cargo_dir = env!("CARGO_MANIFEST_DIR");
    config.proxy.cert_chain = format!("{cargo_dir}/assets/cert.pem");
    config.proxy.cert_key = format!("{cargo_dir}/assets/cert.key");
    Proxy::new(config, None)
        .await
        .expect("failed to create app state")
}

#[tokio::test]
async fn test_empty_config() {
    let state = create_test_state().await;
    let wg_config = state.lock().generate_wg_config().unwrap();
    insta::assert_snapshot!(wg_config);
}

#[tokio::test]
async fn test_config() {
    let state = create_test_state().await;
    let mut info = state
        .lock()
        .new_client_by_id("test-id-0", "app-id-0", "test-pubkey-0")
        .unwrap();

    info.reg_time = SystemTime::UNIX_EPOCH;
    info.last_seen = SystemTime::UNIX_EPOCH;
    insta::assert_debug_snapshot!(info);
    let mut info1 = state
        .lock()
        .new_client_by_id("test-id-1", "app-id-1", "test-pubkey-1")
        .unwrap();
    info1.reg_time = SystemTime::UNIX_EPOCH;
    info1.last_seen = SystemTime::UNIX_EPOCH;
    insta::assert_debug_snapshot!(info1);
    let wg_config = state.lock().generate_wg_config().unwrap();
    insta::assert_snapshot!(wg_config);
}
