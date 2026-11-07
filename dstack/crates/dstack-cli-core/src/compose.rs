// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! build the app-compose manifest — the JSON document the VMM hashes (to derive
//! the app id) and deploys. The raw docker-compose YAML is embedded as a string.

use dstack_types::KeyProviderKind;
use serde_json::json;

/// build a minimal app-compose manifest from a docker-compose YAML body
/// (single-node, no gateway).
///
/// `kms_enabled` selects KMS mode (deterministic, upgradeable per-app keys);
/// gateway and local-key-provider are off for the direct-port single-node flow.
pub fn build_app_compose(name: &str, docker_compose_yaml: &str, kms_enabled: bool) -> String {
    build_app_compose_with_runtime(
        name,
        docker_compose_yaml,
        kms_enabled,
        "docker-compose",
        None,
    )
}

/// Build an app-compose manifest with an explicitly selected compose frontend.
/// `snapshotter` is meaningful only for `nerdctl-compose`.
pub fn build_app_compose_with_runtime(
    name: &str,
    docker_compose_yaml: &str,
    kms_enabled: bool,
    runner: &str,
    snapshotter: Option<&str>,
) -> String {
    build_app_compose_with_runtime_and_volumes(
        name,
        docker_compose_yaml,
        if kms_enabled {
            KeyProviderKind::Kms
        } else {
            KeyProviderKind::None
        },
        runner,
        snapshotter,
        &[],
    )
}

/// Build an app-compose manifest with measured verity volume declarations.
pub fn build_app_compose_with_runtime_and_volumes(
    name: &str,
    docker_compose_yaml: &str,
    key_provider: KeyProviderKind,
    runner: &str,
    snapshotter: Option<&str>,
    verity_volumes: &[dstack_types::VerityVolume],
) -> String {
    let mut manifest = json!({
        "manifest_version": if runner == "nerdctl-compose" { json!("3") } else { json!(2) },
        "name": name,
        "runner": runner,
        "docker_compose_file": docker_compose_yaml,
        "kms_enabled": key_provider.is_kms(),
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
    if let Some(snapshotter) = snapshotter {
        manifest["snapshotter"] = json!(snapshotter);
    }
    if !verity_volumes.is_empty() {
        manifest["verity_volumes"] = json!(verity_volumes);
    }
    // Preserve legacy KMS/None manifest bytes, which determine app identity.
    if !matches!(key_provider, KeyProviderKind::Kms | KeyProviderKind::None) {
        manifest["key_provider"] = json!(key_provider);
    }
    // pretty-print via Value's Display (`{:#}`) — infallible, and byte-identical
    // to serde_json::to_string_pretty (avoids an expect on an unfailable Result).
    format!("{manifest:#}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_provider_matches_previous_cli_manifest_encoding() {
        let volumes = [dstack_types::VerityVolume {
            source: "test.img".into(),
            verity_root: [1; 32],
            target: "/test".into(),
        }];
        for volumes in [&[][..], &volumes[..]] {
            let build = |provider| {
                build_app_compose_with_runtime_and_volumes(
                    "test",
                    "",
                    provider,
                    "nerdctl-compose",
                    Some("soci"),
                    volumes,
                )
            };
            for provider in [
                KeyProviderKind::Snp,
                KeyProviderKind::Local,
                KeyProviderKind::Tpm,
            ] {
                // The old CLI serialized a legacy manifest, then inserted the provider.
                let mut legacy: serde_json::Value =
                    serde_json::from_str(&build(KeyProviderKind::None)).unwrap();
                legacy["key_provider"] = json!(provider);
                assert_eq!(build(provider), format!("{legacy:#}"));
            }
        }
    }
}
