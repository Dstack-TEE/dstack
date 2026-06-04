// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::{errors::AppError, state::AppState};

/// Matches the BootInfo struct sent by dstack-kms (camelCase JSON).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootInfo {
    pub mr_aggregated: String,
    pub os_image_hash: String,
    // present in the wire format but not used for P0 auth decisions
    #[allow(dead_code)]
    pub mr_system: Option<String>,
    pub app_id: String,
    pub compose_hash: String,
    pub instance_id: String,
    pub device_id: String,
    pub tcb_status: Option<String>,
    // present in the wire format but not used for P0 auth decisions
    #[allow(dead_code)]
    pub advisory_ids: Option<Vec<String>>,
}

/// Matches the BootResponse expected by dstack-kms (camelCase JSON).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootResponse {
    pub is_allowed: bool,
    pub reason: String,
    pub gateway_app_id: String,
}

/// Matches the AuthApiInfoResponse expected by dstack-kms (camelCase JSON).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthApiInfoResponse {
    pub status: String,
    pub kms_contract_addr: String,
    pub gateway_app_id: String,
    pub chain_id: u64,
    pub app_implementation: String,
}

fn normalize_hex(s: &str) -> String {
    let s = s.to_lowercase();
    if s.starts_with("0x") {
        s
    } else {
        format!("0x{}", s)
    }
}

/// GET / — info endpoint consumed by dstack-kms get_info().
pub async fn info_handler() -> Json<AuthApiInfoResponse> {
    Json(AuthApiInfoResponse {
        status: "ok".to_string(),
        kms_contract_addr: "0x0000000000000000000000000000000000000000".to_string(),
        gateway_app_id: "".to_string(),
        chain_id: 0,
        app_implementation: "0x0000000000000000000000000000000000000000".to_string(),
    })
}

/// POST /bootAuth/app
pub async fn app_boot_auth(
    State(state): State<Arc<AppState>>,
    Json(boot_info): Json<BootInfo>,
) -> Result<Json<BootResponse>, AppError> {
    tracing::info!(
        app_id = %boot_info.app_id,
        compose_hash = %boot_info.compose_hash,
        instance_id = %boot_info.instance_id,
        "app boot auth request"
    );
    let result = check_app_boot(&state, &boot_info).await;
    tracing::info!(is_allowed = result.is_allowed, reason = %result.reason, "app boot auth result");
    Ok(Json(result))
}

/// POST /bootAuth/kms
pub async fn kms_boot_auth(
    State(state): State<Arc<AppState>>,
    Json(boot_info): Json<BootInfo>,
) -> Result<Json<BootResponse>, AppError> {
    tracing::info!(
        os_image_hash = %boot_info.os_image_hash,
        mr_aggregated = %boot_info.mr_aggregated,
        instance_id = %boot_info.instance_id,
        "kms boot auth request"
    );
    let result = check_kms_boot(&state, &boot_info).await;
    tracing::info!(is_allowed = result.is_allowed, reason = %result.reason, "kms boot auth result");
    Ok(Json(result))
}

async fn check_app_boot(state: &AppState, boot_info: &BootInfo) -> BootResponse {
    let bundle_guard = state.auth_bundle.read().await;
    let Some(bundle) = bundle_guard.as_ref() else {
        return BootResponse {
            is_allowed: false,
            reason: "no auth bundle installed".to_string(),
            gateway_app_id: "".to_string(),
        };
    };

    let gateway_app_id = bundle["gateway_app_id"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // check OS image
    if let Some(result) = check_os_image(bundle, &boot_info.os_image_hash, &gateway_app_id) {
        return result;
    }

    // check TCB status
    if let Some(result) = check_tcb_status(bundle, boot_info, &gateway_app_id) {
        return result;
    }

    let app_id = normalize_hex(&boot_info.app_id);
    let compose_hash = normalize_hex(&boot_info.compose_hash);
    let device_id = normalize_hex(&boot_info.device_id);

    let apps = match bundle["app_whitelist"].as_array() {
        Some(a) => a,
        None => {
            return BootResponse {
                is_allowed: false,
                reason: "no apps in auth bundle".to_string(),
                gateway_app_id,
            }
        }
    };

    let app = apps.iter().find(|a| {
        a["app_id"]
            .as_str()
            .map(|id| normalize_hex(id) == app_id)
            .unwrap_or(false)
    });

    let Some(app) = app else {
        return BootResponse {
            is_allowed: false,
            reason: "app not registered".to_string(),
            gateway_app_id,
        };
    };

    // check compose hash ∈ allowed_launcher_digests — "*" wildcard allows any (dev)
    let raw_hashes: Vec<&str> = app["allowed_launcher_digests"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|h| h.as_str()).collect())
        .unwrap_or_default();

    let wildcard = raw_hashes.contains(&"*");
    let allowed_hashes: Vec<String> = raw_hashes.iter().map(|h| normalize_hex(h)).collect();

    if !wildcard && !allowed_hashes.contains(&compose_hash) {
        return BootResponse {
            is_allowed: false,
            reason: "compose hash not allowed".to_string(),
            gateway_app_id,
        };
    }

    // check compose hash not revoked
    let revoked_launcher_hashes: Vec<String> = app["revocations"]["launcher_hashes"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|h| h.as_str())
                .map(normalize_hex)
                .collect()
        })
        .unwrap_or_default();

    if revoked_launcher_hashes.contains(&compose_hash) {
        return BootResponse {
            is_allowed: false,
            reason: "compose hash is revoked".to_string(),
            gateway_app_id,
        };
    }

    // check image digest not revoked
    let os_image_hash = normalize_hex(&boot_info.os_image_hash);
    let revoked_images: Vec<String> = app["revocations"]["image_digests"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|h| h.as_str())
                .map(normalize_hex)
                .collect()
        })
        .unwrap_or_default();

    if revoked_images.contains(&os_image_hash) {
        return BootResponse {
            is_allowed: false,
            reason: "OS image digest is revoked".to_string(),
            gateway_app_id,
        };
    }

    // check device
    if !check_device_allowed(app, &device_id) {
        return BootResponse {
            is_allowed: false,
            reason: "app is not allowed to boot on this device".to_string(),
            gateway_app_id,
        };
    }

    BootResponse {
        is_allowed: true,
        reason: "".to_string(),
        gateway_app_id,
    }
}

async fn check_kms_boot(state: &AppState, boot_info: &BootInfo) -> BootResponse {
    let bundle_guard = state.auth_bundle.read().await;
    let Some(bundle) = bundle_guard.as_ref() else {
        return BootResponse {
            is_allowed: false,
            reason: "no auth bundle installed".to_string(),
            gateway_app_id: "".to_string(),
        };
    };

    let gateway_app_id = bundle["gateway_app_id"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // check OS image — this is the FAIL-CLOSED mandatory gate for the KMS too.
    if let Some(result) = check_os_image(bundle, &boot_info.os_image_hash, &gateway_app_id) {
        return result;
    }

    // check TCB status
    if let Some(result) = check_tcb_status(bundle, boot_info, &gateway_app_id) {
        return result;
    }

    let mr_aggregated = normalize_hex(&boot_info.mr_aggregated);
    let device_id = normalize_hex(&boot_info.device_id);

    let kms = &bundle["kms"];

    // check aggregated MR — an OPTIONAL extra constraint (empty = not pinned).
    // This is intentionally not the fail-closed gate: on GCP, mr_aggregated folds
    // in PCR0 (the vTPM firmware/launch measurement) which changes per instance,
    // so it can't be pinned. The mandatory gate is os_image (checked above) +
    // the authority-side os_image_hash/compose_hash/key_provider=tpm whitelist.
    let allowed_mrs: Vec<String> = kms["mr_aggregated"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.as_str())
                .map(normalize_hex)
                .collect()
        })
        .unwrap_or_default();

    if !allowed_mrs.is_empty() && !allowed_mrs.contains(&mr_aggregated) {
        return BootResponse {
            is_allowed: false,
            reason: "aggregated MR not allowed".to_string(),
            gateway_app_id,
        };
    }

    // check device
    if !check_device_allowed(kms, &device_id) {
        return BootResponse {
            is_allowed: false,
            reason: "KMS is not allowed to boot on this device".to_string(),
            gateway_app_id,
        };
    }

    BootResponse {
        is_allowed: true,
        reason: "".to_string(),
        gateway_app_id,
    }
}

fn check_os_image(
    bundle: &serde_json::Value,
    os_image_hash: &str,
    gateway_app_id: &str,
) -> Option<BootResponse> {
    let os_image_hash = normalize_hex(os_image_hash);
    let allowed: Vec<String> = bundle["os_images"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|h| h.as_str())
                .map(normalize_hex)
                .collect()
        })
        .unwrap_or_default();

    // FAIL-CLOSED: an unconfigured (empty) whitelist denies, just like a non-match.
    if !allowed.contains(&os_image_hash) {
        let reason = if allowed.is_empty() {
            "os_images whitelist not configured (fail-closed)"
        } else {
            "OS image is not allowed"
        };
        return Some(BootResponse {
            is_allowed: false,
            reason: reason.to_string(),
            gateway_app_id: gateway_app_id.to_string(),
        });
    }
    None
}

fn check_tcb_status(
    bundle: &serde_json::Value,
    boot_info: &BootInfo,
    gateway_app_id: &str,
) -> Option<BootResponse> {
    let tcb_status = boot_info.tcb_status.as_deref().unwrap_or("");
    let allowed: Vec<String> = bundle["allowed_tcb_statuses"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["UpToDate".to_string()]);
    // FAIL-CLOSED: a missing/empty or unlisted TCB status denies.
    if tcb_status.is_empty() || !allowed.iter().any(|s| s == tcb_status) {
        return Some(BootResponse {
            is_allowed: false,
            reason: "TCB status not acceptable".to_string(),
            gateway_app_id: gateway_app_id.to_string(),
        });
    }
    None
}

fn check_device_allowed(config: &serde_json::Value, device_id: &str) -> bool {
    // Explicit opt-in only (e.g. GCP, where device_id isn't pinned).
    if config["allow_any_device"].as_bool().unwrap_or(false) {
        return true;
    }
    let devices: Vec<String> = config["devices"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|d| d.as_str())
                .map(normalize_hex)
                .collect()
        })
        .unwrap_or_default();
    // FAIL-CLOSED: an empty device list denies (was: empty → allow).
    devices.contains(&device_id.to_string())
}
