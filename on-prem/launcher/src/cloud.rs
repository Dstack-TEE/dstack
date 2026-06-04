// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0
//! Cloud-provider seam — the only cloud-specific code in the launcher.
//!
//! Everything else (KMS RA-TLS, key-broker mTLS, JWE decrypt, compose) is
//! cloud-agnostic. The one provider-specific need is authenticating skopeo to
//! the customer's private container registry while air-gapped. Today that's GCP
//! Artifact Registry via the instance metadata server; another cloud (e.g. AWS
//! ECR) would add its own branch here behind the same `registry_auth_token()`.

use std::process::Command;

/// A short-lived bearer token + username for `skopeo --src-creds <user>:<token>`,
/// or None when the registry needs no auth (e.g. a public registry).
pub struct RegistryAuth {
    pub username: String,
    pub token: String,
}

/// Resolve registry credentials from the current cloud environment.
/// Best-effort: returns None off-cloud / on a public registry (skopeo then
/// pulls anonymously).
pub fn registry_auth_token() -> Option<RegistryAuth> {
    gcp_artifact_registry_token().map(|token| RegistryAuth {
        username: "oauth2accesstoken".to_string(),
        token,
    })
}

/// Best-effort GCP service-account access token from the metadata server, for
/// authenticating skopeo to Artifact Registry. None outside GCP.
fn gcp_artifact_registry_token() -> Option<String> {
    let out = Command::new("curl")
        .args([
            "-s", "-H", "Metadata-Flavor: Google",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let key = "\"access_token\":\"";
    let start = body.find(key)? + key.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
