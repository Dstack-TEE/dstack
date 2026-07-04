// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! build the app-compose manifest — the JSON document the VMM hashes (to derive
//! the app id) and deploys. The raw docker-compose YAML is embedded as a string.

use serde_json::json;

/// build a minimal app-compose manifest from a docker-compose YAML body
/// (single-node, no gateway).
///
/// `kms_enabled` selects KMS mode (deterministic, upgradeable per-app keys);
/// gateway and local-key-provider are off for the direct-port single-node flow.
///
/// `verity_volumes` is a list of `(verity_root, target)` pairs. Each becomes a
/// measured `verity_volumes` entry, so the CVM only seeds content matching the
/// attested root. Empty for a normal deploy.
pub fn build_app_compose(
    name: &str,
    docker_compose_yaml: &str,
    kms_enabled: bool,
    verity_volumes: &[(String, String)],
) -> String {
    let mut manifest = json!({
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
        // don't block boot on `chronyc waitsync` — the manifest default is true,
        // but the single-node direct-port flow has no gateway/RA-TLS that needs a
        // pre-synced clock, and the strict wait hard-fails (→ reboot loop) whenever
        // chrony has no usable source. chronyd still syncs in the background.
        // (NTS is also currently broken in guest images — see dstack#745.)
        "secure_time": false,
    });
    if !verity_volumes.is_empty() {
        manifest["verity_volumes"] = json!(verity_volumes
            .iter()
            .map(|(root, target)| json!({ "verity_root": root, "target": target }))
            .collect::<Vec<_>>());
    }
    // pretty-print via Value's Display (`{:#}`) — infallible, and byte-identical
    // to serde_json::to_string_pretty (avoids an expect on an unfailable Result).
    format!("{manifest:#}")
}
