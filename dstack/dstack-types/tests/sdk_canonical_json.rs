// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn canonical_sdk_json_round_trips() {
    // Byte-for-byte what the Python/Go/JS SDKs emit for this manifest; all
    // three hash it to 81f9e7d7...  The guest hashes the file it is given, so
    // agreement means the guest must accept exactly these bytes and re-emit
    // them unchanged.
    let canonical = r#"{"docker_compose_file":"services:\n  w:\n    image: x && y\n","kms_enabled":true,"manifest_version":"3","name":"a","requirements":{"health_check":true,"health_status_file":"/dstack/health","launch_token_hash":"ff00"},"runner":"docker-compose"}"#;
    let compose: dstack_types::AppCompose =
        serde_json::from_str(canonical).expect("guest parses SDK output");
    let requirements = compose.requirements.as_ref().expect("requirements");
    assert!(requirements.health_check);
    assert_eq!(
        requirements.health_status_file.as_deref(),
        Some("/dstack/health")
    );
}

#[test]
fn the_nested_shape_is_rejected() {
    // The shape this replaced. Rejected rather than ignored, so an app-compose
    // written against a pre-release SDK cannot deploy and silently lose its
    // health gating.
    let nested = r#"{"runner":"bash","requirements":{"health_check":{"enabled":true}}}"#;
    assert!(serde_json::from_str::<dstack_types::AppCompose>(nested).is_err());
}
