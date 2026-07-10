// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! build the app-compose manifest — the JSON document the VMM hashes (to derive
//! the app id) and deploys. The raw docker-compose YAML is embedded as a string.

use serde_json::json;

/// build a minimal app-compose manifest from a docker-compose YAML body
/// (single-node, no gateway).
///
/// `kms_enabled` selects KMS mode (deterministic, upgradeable per-app keys).
/// `no_tee` is development-only and requires KMS to be disabled by the caller.
pub fn build_app_compose(
    name: &str,
    docker_compose_yaml: &str,
    kms_enabled: bool,
    no_tee: bool,
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
    if no_tee {
        manifest["no_tee"] = true.into();
    }
    // pretty-print via Value's Display (`{:#}`) — infallible, and byte-identical
    // to serde_json::to_string_pretty (avoids an expect on an unfailable Result).
    format!("{manifest:#}")
}

#[cfg(test)]
mod tests {
    use super::build_app_compose;

    #[test]
    fn no_tee_is_emitted_only_when_enabled() {
        let tee: serde_json::Value =
            serde_json::from_str(&build_app_compose("app", "services: {}", true, false)).unwrap();
        assert!(tee.get("no_tee").is_none());

        let no_tee: serde_json::Value =
            serde_json::from_str(&build_app_compose("app", "services: {}", false, true)).unwrap();
        assert_eq!(no_tee["no_tee"], true);
        assert_eq!(no_tee["kms_enabled"], false);
    }
}
