// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-auth` — the single-operator KMS auth webhook (Rust reimplementation
//! of `auth-simple`).
//!
//! Runs on the host as `dstack-auth.service`; the KMS-in-CVM reaches it at
//! `http://10.0.2.2:<port>` under user-mode networking and POSTs `BootInfo` to
//! `/authorizeApp` (compose-hash allowlist) and `/authorizeKms` (mrAggregated
//! allowlist). Legacy `/bootAuth/*` routes remain available for bootstrap. The allowlist JSON is re-read on every request, so `dstack run`
//! can add an app without a restart. Fails closed: a missing/invalid allowlist
//! denies everything.
//!
//! Deliberate single-node deviation from `auth-simple`: it does NOT enforce
//! `tcbStatus == UpToDate`. Real TDX hosts routinely report a non-`UpToDate`
//! TCB (microcode / TDX-module behind), and in the single-node model the
//! operator already controls and trusts their own host, so a hard TCB gate
//! would be friction without a corresponding trust gain here. Re-add the check
//! (capture `tcbStatus`, deny unless `UpToDate`) if this grows into a
//! multi-tenant / hosted deployment.

use anyhow::{Context, Result};
use clap::Parser;
use dstack_types::authorization::AuthorizationOperation as Operation;
use rocket::http::Status;
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
    /// the root epoch the asking KMS serves and its chain hash; absent from a
    /// KMS that predates root epochs, and from KMS checks made while onboarding.
    root_epoch: Option<usize>,
    root_epoch_hash: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BootResponse {
    is_allowed: bool,
    gateway_app_id: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationRequest {
    operation: Operation,
    #[serde(flatten)]
    boot_info: BootInfo,
    requested_root_epoch: Option<u32>,
    requested_app_epoch: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationResult {
    is_allowed: bool,
    rejection_reason: String,
    gateway_app_id: String,
    current_root_epoch: usize,
    current_root_epoch_hash: String,
    current_app_epoch: u32,
}

/// the current KMS root epoch and its chain hash, which commits to the root
/// public keys of epochs 0..=number.
struct EpochInfo {
    number: usize,
    hash: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Allowlist {
    os_images: Vec<String>,
    kms_contract_addr: String,
    gateway_app_id: String,
    kms: KmsRules,
    apps: HashMap<String, AppRules>,
    /// root public keys of each KMS root epoch, indexed by epoch; append only.
    root_epochs: Vec<RootEpoch>,
    /// the root epoch KMS instances serve; raise it once every node holds it.
    current_root_epoch: usize,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase", default)]
struct RootEpoch {
    ca_pubkey: String,
    k256_pubkey: String,
}

impl Allowlist {
    fn app(&self, app_id: &str) -> Option<&AppRules> {
        let app_id = norm(app_id);
        self.apps
            .iter()
            .find(|(id, _)| norm(id) == app_id)
            .map(|(_, app)| app)
    }

    /// `None` only when no epoch is configured; invalid configuration is an error.
    fn current_root_epoch(&self) -> Result<Option<EpochInfo>> {
        if self.root_epochs.is_empty() && self.current_root_epoch == 0 {
            return Ok(None);
        }
        u32::try_from(self.current_root_epoch).context("root epoch exceeds uint32")?;
        let epochs = self
            .root_epochs
            .get(..=self.current_root_epoch)
            .context("currentRootEpoch is not a configured root epoch")?;
        let keys = epochs
            .iter()
            .map(|e| {
                Ok((
                    hex::decode(norm(&e.ca_pubkey)).context("invalid root epoch CA public key")?,
                    hex::decode(norm(&e.k256_pubkey))
                        .context("invalid root epoch k256 public key")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let hashes = dstack_types::root_epoch::chain_hashes(
            keys.iter().map(|(ca, k256)| (&ca[..], &k256[..])),
        );
        Ok(Some(EpochInfo {
            number: self.current_root_epoch,
            hash: format!("0x{}", hex::encode(hashes[self.current_root_epoch])),
        }))
    }
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
    current_app_epoch: u32,
    compose_hashes: Vec<String>,
    devices: Vec<String>,
    allow_any_device: bool,
}

/// normalize a hex string for comparison: trim, drop a `0x`/`0X` prefix,
/// lowercase. MUST stay in sync with `dstack-cli-core::config::norm_hex` — both
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

/// allow, provided the asking KMS serves the current root epoch with the
/// registered keys up to it. A KMS that predates root epochs reports none and
/// holds only epoch 0; KMS checks made while onboarding carry none.
fn allow(info: &BootInfo, is_kms: bool, al: &Allowlist) -> BootResponse {
    let current = match al.current_root_epoch() {
        Ok(current) => current,
        Err(error) => return deny(al, &format!("invalid root epoch configuration: {error}")),
    };
    let current_epoch = current.as_ref().map_or(0, |c| c.number);
    let denial = match (info.root_epoch, &current) {
        (None, _) if is_kms || current_epoch == 0 => None,
        (None, _) => Some(format!(
            "root epoch {current_epoch} is current, but the KMS reports none"
        )),
        (Some(0), None) => None,
        (Some(epoch), None) => Some(format!("root epoch {epoch} is not registered")),
        (Some(epoch), Some(_)) if epoch != current_epoch => Some(format!(
            "the KMS serves root epoch {epoch}, but {current_epoch} is current"
        )),
        (Some(_), Some(c)) if info.root_epoch_hash.as_deref().map(norm) != Some(norm(&c.hash)) => {
            Some(format!(
                "the KMS root keys up to epoch {current_epoch} are not the registered ones"
            ))
        }
        _ => None,
    };
    match denial {
        Some(reason) => deny(al, &reason),
        None => BootResponse {
            is_allowed: true,
            gateway_app_id: al.gateway_app_id.clone(),
            reason: "ok".to_string(),
        },
    }
}

fn app_policy(info: &BootInfo, al: &Allowlist) -> BootResponse {
    if !al.os_images.is_empty() && !contains(&al.os_images, &info.os_image_hash) {
        return deny(al, "os image not allowed");
    }
    let Some(app) = al.app(&info.app_id) else {
        return deny(al, "app not registered");
    };
    if !contains(&app.compose_hashes, &info.compose_hash) {
        return deny(al, "compose hash not allowed");
    }
    if !device_ok(app.allow_any_device, &app.devices, &info.device_id) {
        return deny(al, "device not allowed");
    }
    BootResponse {
        is_allowed: true,
        gateway_app_id: al.gateway_app_id.clone(),
        reason: String::new(),
    }
}

fn kms_policy(info: &BootInfo, al: &Allowlist) -> BootResponse {
    if !contains(&al.kms.mr_aggregated, &info.mr_aggregated) {
        return deny(al, "kms mrAggregated not allowed");
    }
    if !device_ok(al.kms.allow_any_device, &al.kms.devices, &info.device_id) {
        return deny(al, "device not allowed");
    }
    BootResponse {
        is_allowed: true,
        gateway_app_id: al.gateway_app_id.clone(),
        reason: String::new(),
    }
}

fn check_app(info: &BootInfo, al: &Allowlist) -> BootResponse {
    if al
        .app(&info.app_id)
        .is_some_and(|app| app.current_app_epoch != 0)
    {
        return deny(al, "app epoch requires epoch-aware authorization");
    }
    let result = app_policy(info, al);
    if result.is_allowed {
        allow(info, false, al)
    } else {
        result
    }
}

fn check_kms(info: &BootInfo, al: &Allowlist) -> BootResponse {
    let result = kms_policy(info, al);
    if result.is_allowed {
        allow(info, true, al)
    } else {
        result
    }
}

fn authorize(
    request: &AuthorizationRequest,
    is_kms: bool,
    al: &Allowlist,
) -> Result<AuthorizationResult> {
    let current = al.current_root_epoch()?;
    let mut result = AuthorizationResult {
        is_allowed: false,
        rejection_reason: String::new(),
        gateway_app_id: al.gateway_app_id.clone(),
        current_root_epoch: current.as_ref().map_or(0, |epoch| epoch.number),
        current_root_epoch_hash: current.as_ref().map_or_else(
            || format!("0x{}", "00".repeat(32)),
            |epoch| epoch.hash.clone(),
        ),
        current_app_epoch: if is_kms {
            0
        } else {
            al.app(&request.boot_info.app_id)
                .map_or(0, |app| app.current_app_epoch)
        },
    };
    let info = &request.boot_info;
    result.rejection_reason = if request.operation.is_kms() != is_kms {
        "invalid authorization operation".into()
    } else if current.is_none() && request.operation != Operation::KmsBootstrap {
        "root epoch not registered".into()
    } else if request
        .requested_root_epoch
        .is_some_and(|epoch| epoch as usize > result.current_root_epoch)
    {
        "requested root epoch is not active".into()
    } else if request
        .requested_app_epoch
        .is_some_and(|epoch| epoch > result.current_app_epoch)
    {
        "requested app epoch is not active".into()
    } else if request.operation != Operation::KmsBootstrap && norm(&al.kms_contract_addr).is_empty()
    {
        "kmsContractAddr is not configured".into()
    } else if request.operation != Operation::KmsBootstrap
        && (norm(&info.app_id) == norm(&al.kms_contract_addr)) != is_kms
    {
        "caller does not match authorization scope".into()
    } else {
        let policy = if is_kms {
            kms_policy(info, al)
        } else {
            app_policy(info, al)
        };
        result.is_allowed = policy.is_allowed;
        policy.reason
    };
    Ok(result)
}

fn unavailable(error: anyhow::Error) -> Status {
    rocket::warn!("invalid authorization configuration: {error}");
    Status::ServiceUnavailable
}

#[post("/authorizeApp", data = "<request>")]
fn authorize_app(
    request: Json<AuthorizationRequest>,
    cli: &State<Cli>,
) -> Result<Json<AuthorizationResult>, Status> {
    authorize(&request, false, &load(&cli.config))
        .map(Json)
        .map_err(unavailable)
}

#[post("/authorizeKms", data = "<request>")]
fn authorize_kms(
    request: Json<AuthorizationRequest>,
    cli: &State<Cli>,
) -> Result<Json<AuthorizationResult>, Status> {
    authorize(&request, true, &load(&cli.config))
        .map(Json)
        .map_err(unavailable)
}

#[get("/app/<app_id>")]
fn app_epoch(app_id: &str, cli: &State<Cli>) -> Result<Json<serde_json::Value>, Status> {
    let id = norm(app_id);
    if hex::decode(&id).map_or(true, |bytes| bytes.len() != 20) {
        return Err(Status::BadRequest);
    }
    let al = load(&cli.config);
    Ok(Json(
        json!({ "currentAppEpoch": al.app(&id).map_or(0, |app| app.current_app_epoch) }),
    ))
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
fn info(cli: &State<Cli>) -> Result<Json<serde_json::Value>, Status> {
    info_json(&load(&cli.config)).map(Json).map_err(|error| {
        rocket::warn!("invalid root epoch configuration: {error}");
        Status::ServiceUnavailable
    })
}

fn info_json(al: &Allowlist) -> Result<serde_json::Value> {
    let mut info = json!({
        "status": "ok",
        "kmsContractAddr": al.kms_contract_addr,
        "ethRpcUrl": "",
        "gatewayAppId": al.gateway_app_id,
        "chainId": 0,
        "appImplementation": "",
    });
    if let Some(epoch) = al.current_root_epoch()? {
        info["rootEpoch"] = epoch.number.into();
        info["rootEpochHash"] = epoch.hash.into();
    }
    Ok(info)
}

fn server(cli: Cli) -> rocket::Rocket<rocket::Build> {
    let figment = rocket::Config::figment()
        .merge(("address", cli.address.clone()))
        .merge(("port", cli.port));
    rocket::custom(figment).manage(cli).mount(
        "/",
        routes![
            info,
            boot_app,
            boot_kms,
            authorize_app,
            authorize_kms,
            app_epoch
        ],
    )
}

#[rocket::main]
async fn main() -> Result<()> {
    server(Cli::parse())
        .launch()
        .await
        .map_err(|e| anyhow::anyhow!("auth webhook failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rocket::async_test]
    async fn authorization_routes_use_registered_roots_and_separate_caller_scopes() {
        use rocket::{http::ContentType, local::asynchronous::Client};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        let mut policy = json!({
            "kmsContractAddr": "0x1111111111111111111111111111111111111111",
            "rootEpochs": [{"caPubkey": "aa", "k256Pubkey": "bb"}],
            "osImages": ["aa"],
            "kms": {"mrAggregated": ["bb"]},
            "apps": {"0x2222222222222222222222222222222222222222": {"composeHashes": ["cc"]}}
        });
        std::fs::write(&path, policy.to_string()).unwrap();
        let client = Client::tracked(server(Cli {
            config: path.clone(),
            address: "127.0.0.1".into(),
            port: 0,
        }))
        .await
        .unwrap();
        let kms = json!({"operation": "kms_serve", "appId": "11".repeat(20), "mrAggregated": "bb"});
        let app = json!({"operation": "app_get_key", "appId": "22".repeat(20), "composeHash": "cc", "osImageHash": "aa"});
        for (route, body, allowed) in [
            ("/authorizeKms", kms.clone(), true),
            ("/authorizeApp", app.clone(), true),
            ("/authorizeKms", app.clone(), false),
            ("/authorizeApp", kms.clone(), false),
        ] {
            let response = client
                .post(route)
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            let response: serde_json::Value = response.into_json().await.unwrap();
            assert_eq!(response["isAllowed"], allowed);
            assert_eq!(response["currentRootEpoch"], 0);
            assert_eq!(response["currentAppEpoch"], 0);
            assert_ne!(
                response["currentRootEpochHash"],
                format!("0x{}", "00".repeat(32))
            );
        }
        for operation in [serde_json::Value::Null, json!("unknown")] {
            let mut body = app.clone();
            body["operation"] = operation;
            let response = client
                .post("/authorizeApp")
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await;
            assert!(matches!(
                response.status(),
                Status::BadRequest | Status::UnprocessableEntity
            ));
        }
        for field in ["requestedRootEpoch", "requestedAppEpoch"] {
            let mut body = app.clone();
            body[field] = 1.into();
            let response: serde_json::Value = client
                .post("/authorizeApp")
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await
                .into_json()
                .await
                .unwrap();
            assert_eq!(response["isAllowed"], false);
        }
        policy["rootEpochs"] = json!([]);
        std::fs::write(&path, policy.to_string()).unwrap();
        let response: serde_json::Value = client
            .post("/authorizeKms")
            .header(ContentType::JSON)
            .body(kms.to_string())
            .dispatch()
            .await
            .into_json()
            .await
            .unwrap();
        assert_eq!(response["isAllowed"], false);
        assert_eq!(
            response["currentRootEpochHash"],
            format!("0x{}", "00".repeat(32))
        );
        policy["currentRootEpoch"] = 1.into();
        std::fs::write(&path, policy.to_string()).unwrap();
        assert_eq!(
            client
                .post("/authorizeApp")
                .header(ContentType::JSON)
                .body(app.to_string())
                .dispatch()
                .await
                .status(),
            Status::ServiceUnavailable
        );
    }

    #[rocket::async_test]
    async fn app_epochs_share_normalized_policy_and_reject_legacy_boot() {
        use rocket::{http::ContentType, local::asynchronous::Client};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        let client = Client::tracked(server(Cli {
            config: path.clone(),
            address: "127.0.0.1".into(),
            port: 0,
        }))
        .await
        .unwrap();
        let id = "ab".repeat(20);
        for configured_id in [
            id.clone(),
            format!("0X{}", id.to_uppercase()),
            format!("0x{id}"),
        ] {
            let policy = json!({
                "kmsContractAddr": "11".repeat(20),
                "rootEpochs": [{"caPubkey": "aa", "k256Pubkey": "bb"}, {"caPubkey": "cc", "k256Pubkey": "dd"}],
                "currentRootEpoch": 1,
                "apps": {configured_id: {"currentAppEpoch": 2, "composeHashes": ["ee"]}}
            });
            std::fs::write(&path, policy.to_string()).unwrap();
            let response: serde_json::Value = client
                .get(format!("/app/0x{id}"))
                .dispatch()
                .await
                .into_json()
                .await
                .unwrap();
            assert_eq!(response["currentAppEpoch"], 2);
            for selectors in [
                json!({}),
                json!({"requestedRootEpoch": 0, "requestedAppEpoch": 0}),
                json!({"requestedRootEpoch": 1, "requestedAppEpoch": 2}),
                json!({"requestedAppEpoch": 3}),
                json!({"requestedRootEpoch": 2}),
            ] {
                let allowed =
                    selectors["requestedAppEpoch"] != 3 && selectors["requestedRootEpoch"] != 2;
                let mut request = selectors;
                request["appId"] = id.clone().into();
                request["composeHash"] = "ee".into();
                let response: serde_json::Value = client
                    .post("/authorizeApp")
                    .header(ContentType::JSON)
                    .body(request.to_string())
                    .dispatch()
                    .await
                    .into_json()
                    .await
                    .unwrap();
                assert_eq!(response["isAllowed"], allowed);
                assert_eq!(response["currentAppEpoch"], 2);
                assert_eq!(response["currentRootEpoch"], 1);
            }
            let body = json!({"appId": id, "composeHash": "ee"});
            let response: serde_json::Value = client
                .post("/bootAuth/app")
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await
                .into_json()
                .await
                .unwrap();
            assert_eq!(response["isAllowed"], false);
        }
        assert_eq!(
            client.get("/app/not-hex").dispatch().await.status(),
            Status::BadRequest
        );
    }

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

    #[test]
    fn allows_only_a_kms_serving_the_current_root_epoch() {
        // Shared with the DstackKms contract tests.
        let h0 = "0x10ab6b6c8e7601901b0f1767985bf40d35bf3129e0866fe12dcc7c8f04a298f2";
        let h1 = "0x50152a82023f2219a31723b476c13bc5f608ab4147946dabdec15d4f3d648ed4";
        let mut al: Allowlist = serde_json::from_str(
            r#"{"kms":{"mrAggregated":["0xMR"]},
                "rootEpochs":[{"caPubkey":"0x3059301306072a8648ce3d020106082a8648ce3d03010703420004a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0","k256Pubkey":"0x02b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"},
                              {"caPubkey":"0x3059301306072a8648ce3d020106082a8648ce3d03010703420004a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","k256Pubkey":"0x02b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"}]}"#,
        )
        .unwrap();
        let info = |epoch: Option<usize>, hash: &str| BootInfo {
            mr_aggregated: "0xMR".into(),
            root_epoch: epoch,
            root_epoch_hash: Some(hash.into()),
            ..Default::default()
        };
        assert_eq!(info_json(&al).unwrap()["rootEpochHash"], h0);
        assert!(check_kms(&info(Some(0), h0), &al).is_allowed);

        al.current_root_epoch = 1;
        assert_eq!(info_json(&al).unwrap()["rootEpoch"], 1);
        assert_eq!(info_json(&al).unwrap()["rootEpochHash"], h1);
        assert!(check_kms(&info(Some(1), &h1.to_uppercase()), &al).is_allowed);
        assert!(!check_kms(&info(Some(0), h0), &al).is_allowed);
        assert!(!check_kms(&info(Some(1), h0), &al).is_allowed);
        // onboarding checks carry no epoch
        assert!(check_kms(&info(None, ""), &al).is_allowed);

        al.current_root_epoch = 2;
        assert!(al.current_root_epoch().is_err());
        assert!(info_json(&al).is_err());
        assert!(!check_kms(&info(Some(1), h1), &al).is_allowed);
    }

    #[test]
    fn a_kms_predating_root_epochs_is_cut_off_once_one_is_current() {
        let mut al = allowlist();
        let info = boot("0xapp1", "0xhash", "0ximg");
        assert!(check_app(&info, &al).is_allowed);
        al.root_epochs = vec![
            RootEpoch {
                ca_pubkey: "0xa0".into(),
                k256_pubkey: "0xb0".into(),
            },
            RootEpoch {
                ca_pubkey: "0xa1".into(),
                k256_pubkey: "0xb1".into(),
            },
        ];
        assert!(check_app(&info, &al).is_allowed);
        al.current_root_epoch = 1;
        assert!(!check_app(&info, &al).is_allowed);
    }

    #[test]
    fn invalid_root_epochs_deny_legacy_and_epoch_aware_kms() {
        let invalid_configs = [
            json!({"currentRootEpoch": 1}),
            json!({"currentRootEpoch": 1, "rootEpochs": [{"caPubkey": "a0", "k256Pubkey": "b0"}]}),
            json!({"rootEpochs": [{"caPubkey": "invalid", "k256Pubkey": "b0"}]}),
            json!({"rootEpochs": [{"caPubkey": "a0", "k256Pubkey": "invalid"}]}),
        ];
        for config in invalid_configs {
            let epochs: Allowlist = serde_json::from_value(config).unwrap();
            let al = Allowlist {
                root_epochs: epochs.root_epochs,
                current_root_epoch: epochs.current_root_epoch,
                ..allowlist()
            };
            assert!(info_json(&al).is_err());
            for epoch in [None, Some(0), Some(1)] {
                let info = BootInfo {
                    mr_aggregated: "0xMR".into(),
                    root_epoch: epoch,
                    ..boot("0xapp1", "0xhash", "0ximg")
                };
                assert!(!check_app(&info, &al).is_allowed);
                assert!(!check_kms(&info, &al).is_allowed);
            }
        }
    }

    // wire-contract snapshot: BootInfo as the KMS serializes it (camelCase).
    // Keep these field names in sync with the kms BootInfo. `#[serde(default)]`
    // means extra fields are ignored AND a renamed field deserializes to "" —
    // which fails closed, but silently — so this test pins the names we depend
    // on: if the KMS renames one, the matching assertion here breaks first.
    #[test]
    fn deserializes_the_kms_bootinfo_wire_contract() {
        let wire = r#"{
            "teeVariant": "dstack",
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
