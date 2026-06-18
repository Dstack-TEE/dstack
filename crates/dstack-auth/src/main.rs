// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-auth` — the single-operator KMS auth webhook (Rust reimplementation
//! of `auth-simple`).
//!
//! Runs on the host as `dstack-auth.service`; the KMS-in-CVM reaches it at
//! `http://10.0.2.2:<port>` under user-mode networking and POSTs `BootInfo` to
//! `/bootAuth/app` (compose-hash allowlist) and `/bootAuth/kms` (mrAggregated
//! allowlist). The allowlist JSON is re-read on every request, so `dstack run`
//! can add an app without a restart. Fails closed: a missing/invalid allowlist
//! denies everything.
//!
//! Deliberate Tier-1 deviation from `auth-simple`: it does NOT enforce
//! `tcbStatus == UpToDate`. Real TDX hosts routinely report a non-`UpToDate`
//! TCB (microcode / TDX-module behind), and in the single-node model the
//! operator already controls and trusts their own host, so a hard TCB gate
//! would be friction without a corresponding trust gain here. Re-add the check
//! (capture `tcbStatus`, deny unless `UpToDate`) if this grows into a
//! multi-tenant / hosted deployment.

use anyhow::Result;
use clap::Parser;
use rocket::serde::json::Json;
use rocket::{get, post, routes, State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser, Clone)]
#[command(
    name = "dstack-auth",
    version,
    about = "single-operator KMS auth webhook"
)]
struct Cli {
    /// path to the allowlist JSON (re-read on every request).
    #[arg(long, default_value = "/var/lib/dstack/auth-allowlist.json")]
    config: PathBuf,
    /// bind address. Defaults to loopback (reachable from CVMs at 10.0.2.2 via
    /// user-mode networking, and not exposed externally).
    #[arg(long, default_value = "127.0.0.1")]
    address: String,
    /// bind port.
    #[arg(long, default_value_t = 8001)]
    port: u16,
}

/// boot info the KMS sends (camelCase; byte fields are hex strings). Only the
/// fields the allowlist checks are captured; the rest are ignored.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BootInfo {
    mr_aggregated: String,
    os_image_hash: String,
    app_id: String,
    compose_hash: String,
    device_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BootResponse {
    is_allowed: bool,
    gateway_app_id: String,
    reason: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Allowlist {
    os_images: Vec<String>,
    gateway_app_id: String,
    kms: KmsRules,
    apps: HashMap<String, AppRules>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct KmsRules {
    mr_aggregated: Vec<String>,
    devices: Vec<String>,
    allow_any_device: bool,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct AppRules {
    compose_hashes: Vec<String>,
    devices: Vec<String>,
    allow_any_device: bool,
}

/// normalize a hex string for comparison: trim, drop a `0x`/`0X` prefix,
/// lowercase. MUST stay in sync with `dstack-core::config::norm_hex` — both
/// `dstack run` (writing the allowlist) and this webhook (reading it) must
/// agree on the canonical form, or apps are silently denied.
fn norm(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.to_lowercase()
}

fn contains(list: &[String], value: &str) -> bool {
    let v = norm(value);
    list.iter().any(|x| norm(x) == v)
}

/// matches auth-simple: an empty `devices` list means "any device" even when
/// `allowAnyDevice` is false (it only enforces a non-empty list).
fn device_ok(allow_any: bool, devices: &[String], device_id: &str) -> bool {
    allow_any || devices.is_empty() || contains(devices, device_id)
}

fn deny(al: &Allowlist, reason: &str) -> BootResponse {
    BootResponse {
        is_allowed: false,
        gateway_app_id: al.gateway_app_id.clone(),
        reason: reason.to_string(),
    }
}

fn allow(al: &Allowlist) -> BootResponse {
    BootResponse {
        is_allowed: true,
        gateway_app_id: al.gateway_app_id.clone(),
        reason: "ok".to_string(),
    }
}

fn check_app(info: &BootInfo, al: &Allowlist) -> BootResponse {
    if !al.os_images.is_empty() && !contains(&al.os_images, &info.os_image_hash) {
        return deny(al, "os image not allowed");
    }
    let app_id = norm(&info.app_id);
    let Some(app) = al
        .apps
        .iter()
        .find(|(k, _)| norm(k) == app_id)
        .map(|(_, v)| v)
    else {
        return deny(al, "app not registered");
    };
    if !contains(&app.compose_hashes, &info.compose_hash) {
        return deny(al, "compose hash not allowed");
    }
    if !device_ok(app.allow_any_device, &app.devices, &info.device_id) {
        return deny(al, "device not allowed");
    }
    allow(al)
}

fn check_kms(info: &BootInfo, al: &Allowlist) -> BootResponse {
    if !contains(&al.kms.mr_aggregated, &info.mr_aggregated) {
        return deny(al, "kms mrAggregated not allowed");
    }
    if !device_ok(al.kms.allow_any_device, &al.kms.devices, &info.device_id) {
        return deny(al, "device not allowed");
    }
    allow(al)
}

/// load the allowlist, failing closed (deny-all) if it's missing or invalid.
fn load(path: &PathBuf) -> Allowlist {
    match std::fs::read_to_string(path) {
        Ok(body) => serde_json::from_str(&body).unwrap_or_else(|e| {
            rocket::warn!("allowlist {} is invalid: {e}; denying all", path.display());
            Allowlist::default()
        }),
        Err(e) => {
            rocket::warn!("allowlist {} unreadable: {e}; denying all", path.display());
            Allowlist::default()
        }
    }
}

#[post("/bootAuth/app", data = "<info>")]
fn boot_app(info: Json<BootInfo>, cli: &State<Cli>) -> Json<BootResponse> {
    let r = check_app(&info, &load(&cli.config));
    rocket::info!(
        "bootAuth/app app={} compose={} -> allowed={} ({})",
        norm(&info.app_id),
        norm(&info.compose_hash),
        r.is_allowed,
        r.reason
    );
    Json(r)
}

#[post("/bootAuth/kms", data = "<info>")]
fn boot_kms(info: Json<BootInfo>, cli: &State<Cli>) -> Json<BootResponse> {
    let r = check_kms(&info, &load(&cli.config));
    rocket::info!(
        "bootAuth/kms mr={} -> allowed={} ({})",
        norm(&info.mr_aggregated),
        r.is_allowed,
        r.reason
    );
    Json(r)
}

/// info endpoint the KMS GETs to populate its metadata. Single-node: no chain.
#[get("/")]
fn info() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "kmsContractAddr": "",
        "ethRpcUrl": "",
        "gatewayAppId": "",
        "chainId": 0,
        "appImplementation": ""
    }))
}

#[rocket::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let figment = rocket::Config::figment()
        .merge(("address", cli.address.clone()))
        .merge(("port", cli.port));
    rocket::custom(figment)
        .manage(cli)
        .mount("/", routes![info, boot_app, boot_kms])
        .launch()
        .await
        .map_err(|e| anyhow::anyhow!("auth webhook failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist() -> Allowlist {
        serde_json::from_str(
            r#"{
              "osImages": ["0xIMG"],
              "kms": { "mrAggregated": ["0xMR"], "allowAnyDevice": true },
              "apps": { "0xApp1": { "composeHashes": ["0xHASH"], "allowAnyDevice": true } }
            }"#,
        )
        .unwrap()
    }

    fn boot(app: &str, hash: &str, img: &str) -> BootInfo {
        BootInfo {
            app_id: app.into(),
            compose_hash: hash.into(),
            os_image_hash: img.into(),
            ..Default::default()
        }
    }

    #[test]
    fn app_allowed_with_normalized_hex() {
        // differing 0x/case must still match.
        let r = check_app(&boot("APP1", "hash", "img"), &allowlist());
        assert!(r.is_allowed, "{}", r.reason);
    }

    #[test]
    fn app_denied_unknown_app_hash_or_image() {
        let al = allowlist();
        assert!(!check_app(&boot("0xnope", "0xHASH", "0xIMG"), &al).is_allowed);
        assert!(!check_app(&boot("0xApp1", "0xnope", "0xIMG"), &al).is_allowed);
        assert!(!check_app(&boot("0xApp1", "0xHASH", "0xnope"), &al).is_allowed);
    }

    #[test]
    fn kms_allowlist_and_empty_default() {
        let al = allowlist();
        let info = BootInfo {
            mr_aggregated: "0xMR".into(),
            ..Default::default()
        };
        assert!(check_kms(&info, &al).is_allowed);
        // fail closed: empty allowlist denies (the single-node case never calls this).
        assert!(!check_kms(&info, &Allowlist::default()).is_allowed);
    }

    // wire-contract snapshot: BootInfo as the KMS serializes it (camelCase).
    // Keep these field names in sync with the kms BootInfo. `#[serde(default)]`
    // means extra fields are ignored AND a renamed field deserializes to "" —
    // which fails closed, but silently — so this test pins the names we depend
    // on: if the KMS renames one, the matching assertion here breaks first.
    #[test]
    fn deserializes_the_kms_bootinfo_wire_contract() {
        let wire = r#"{
            "attestationMode": "dstack",
            "mrAggregated": "0xAABB",
            "osImageHash": "0xC2AA",
            "mrSystem": "0xdead",
            "appId": "0xApp1",
            "composeHash": "0xHASH",
            "instanceId": "0x01",
            "deviceId": "0xDEV",
            "keyProviderInfo": "kp",
            "tcbStatus": "UpToDate",
            "advisoryIds": []
        }"#;
        let info: BootInfo = serde_json::from_str(wire).expect("kms BootInfo must deserialize");
        assert_eq!(norm(&info.mr_aggregated), "aabb");
        assert_eq!(norm(&info.os_image_hash), "c2aa");
        assert_eq!(norm(&info.app_id), "app1");
        assert_eq!(norm(&info.compose_hash), "hash");
        assert_eq!(norm(&info.device_id), "dev");
        // a check using this payload should pass against a matching allowlist.
        let info2: BootInfo = serde_json::from_str(wire).unwrap();
        let al: Allowlist = serde_json::from_str(
            r#"{"osImages":["0xC2AA"],"apps":{"0xApp1":{"composeHashes":["0xHASH"],"allowAnyDevice":true}}}"#,
        )
        .unwrap();
        assert!(check_app(&info2, &al).is_allowed);
    }
}
