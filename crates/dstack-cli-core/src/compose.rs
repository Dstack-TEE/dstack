// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! build the app-compose manifest — the JSON document the VMM hashes (to derive
//! the app id) and deploys. The raw docker-compose YAML is embedded as a string.

use serde_json::json;

/// build a minimal Tier-1 app-compose manifest from a docker-compose YAML body.
///
/// `kms_enabled` selects KMS mode (deterministic, upgradeable per-app keys);
/// gateway and local-key-provider are off for the direct-port Tier-1 flow.
pub fn build_app_compose(name: &str, docker_compose_yaml: &str, kms_enabled: bool) -> String {
    let manifest = json!({
        "manifest_version": 2,
        "name": name,
        "runner": "docker-compose",
        "docker_compose_file": docker_compose_yaml,
        "kms_enabled": kms_enabled,
        "gateway_enabled": false,
        "local_key_provider_enabled": false,
        "public_logs": true,
        "public_sysinfo": true,
        "no_instance_id": false,
    });
    // pretty-print via Value's Display (`{:#}`) — infallible, and byte-identical
    // to serde_json::to_string_pretty (avoids an expect on an unfailable Result).
    format!("{manifest:#}")
}
