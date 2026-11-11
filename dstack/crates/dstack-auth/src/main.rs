// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-auth` — the file-based KMS auth webhook.
//!
//! Runs on the host as `dstack-auth.service`; the KMS-in-CVM reaches it at
//! `http://10.0.2.2:<port>` under user-mode networking and POSTs `BootInfo` to
//! `/authorizeApp` (compose-hash allowlist) and `/authorizeKms` (mrAggregated
//! allowlist). Legacy `/bootAuth/*` routes remain available for bootstrap. The
//! allowlist JSON is re-read on every request, so `dstack run` can add an app
//! without a restart. Fails closed: a missing/invalid allowlist denies
//! everything.
//!
//! The allowlist format is the one the removed `auth-simple` server used, so
//! its config files load unchanged. One default differs: the TCB status and
//! advisory IDs are checked only when the allowlist sets `allowedTcbStatuses`
//! / `allowedAdvisoryIds` (auth-simple defaulted to `["UpToDate"]` and `[]`).
//! Real TDX hosts routinely report a non-`UpToDate` TCB (microcode / TDX
//! module behind), and in the single-node model the operator already controls
//! and trusts their own host, so a hard TCB gate would be friction without a
//! corresponding trust gain there. Deployments that serve other parties should
//! set both fields.
//!
//! KMS boots are not checked against `osImages`: `kms.mrAggregated` already
//! pins the OS image measurements.

use anyhow::{bail, Context, Result};
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
    /// verifier-derived TCB status, e.g. `UpToDate`; checked only when the
    /// allowlist sets `allowedTcbStatuses`.
    tcb_status: String,
    /// security advisories reported for the platform; checked only when the
    /// allowlist sets `allowedAdvisoryIds`.
    advisory_ids: Vec<String>,
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
    authorized: bool,
    rejection_reason: String,
    gateway_app_id: String,
    current_root_epoch: usize,
    current_root_epoch_hash: String,
    current_app_epoch: u32,
    latest_root_epoch: usize,
    latest_root_epoch_hash: String,
}

/// a KMS root epoch and its chain hash, which commits to the root public keys
/// of epochs 0..=number.
struct EpochInfo {
    number: usize,
    hash: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Allowlist {
    os_images: Vec<String>,
    /// when set, deny unless the reported `tcbStatus` is listed; an empty list
    /// denies everything. Absent: the TCB status is not checked.
    allowed_tcb_statuses: Option<Vec<String>>,
    /// when set, deny any reported advisory ID that is not listed; an empty
    /// list denies any advisory. Absent: advisories are not checked.
    allowed_advisory_ids: Option<Vec<String>>,
    kms_contract_addr: String,
    gateway_app_id: String,
    /// informational, reported by `GET /`.
    chain_id: u64,
    /// informational, reported by `GET /`.
    app_implementation: String,
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
        Ok(self.root_epoch_info()?.map(|(current, _)| current))
    }

    /// the current and the latest configured root epochs; configured epochs
    /// beyond the current one are pending activation.
    fn root_epoch_info(&self) -> Result<Option<(EpochInfo, EpochInfo)>> {
        if self.root_epochs.is_empty() && self.current_root_epoch == 0 {
            return Ok(None);
        }
        u32::try_from(self.root_epochs.len()).context("root epoch exceeds uint32")?;
        if self.current_root_epoch >= self.root_epochs.len() {
            bail!("currentRootEpoch is not a configured root epoch");
        }
        let keys = self
            .root_epochs
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
        let info = |number: usize| EpochInfo {
            number,
            hash: format!("0x{}", hex::encode(hashes[number])),
        };
        Ok(Some((
            info(self.current_root_epoch),
            info(self.root_epochs.len() - 1),
        )))
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

/// An empty `devices` list allows no device; any device needs `allowAnyDevice`.
fn device_ok(allow_any: bool, devices: &[String], device_id: &str) -> bool {
    allow_any || contains(devices, device_id)
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
/// holds only epoch 0, so it is served only until another epoch is activated.
fn allow(info: &BootInfo, al: &Allowlist) -> BootResponse {
    let current = match al.current_root_epoch() {
        Ok(current) => current,
        Err(error) => return deny(al, &format!("invalid root epoch configuration: {error}")),
    };
    let current_epoch = current.as_ref().map_or(0, |c| c.number);
    let denial = match (info.root_epoch, &current) {
        (None, _) if current_epoch == 0 => None,
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

/// the opt-in platform checks shared by app and KMS policy.
fn tcb_denial(info: &BootInfo, al: &Allowlist) -> Option<&'static str> {
    if let Some(allowed) = &al.allowed_tcb_statuses {
        if !allowed.contains(&info.tcb_status) {
            return Some("tcb status not allowed");
        }
    }
    if let Some(allowed) = &al.allowed_advisory_ids {
        if info.advisory_ids.iter().any(|id| !allowed.contains(id)) {
            return Some("advisory id not allowed");
        }
    }
    None
}

fn app_policy(info: &BootInfo, al: &Allowlist) -> BootResponse {
    if let Some(reason) = tcb_denial(info, al) {
        return deny(al, reason);
    }
    if al.os_images.is_empty() {
        return deny(al, "os image allowlist is empty");
    }
    if !contains(&al.os_images, &info.os_image_hash) {
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
    if let Some(reason) = tcb_denial(info, al) {
        return deny(al, reason);
    }
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
        allow(info, al)
    } else {
        result
    }
}

fn check_kms(info: &BootInfo, al: &Allowlist) -> BootResponse {
    let result = kms_policy(info, al);
    if result.is_allowed {
        allow(info, al)
    } else {
        result
    }
}

fn authorize(
    request: &AuthorizationRequest,
    is_kms: bool,
    al: &Allowlist,
) -> Result<AuthorizationResult> {
    let epochs = al.root_epoch_info()?;
    let current = epochs.as_ref().map(|(current, _)| current);
    let latest = epochs.as_ref().map(|(_, latest)| latest);
    let zero_hash = || format!("0x{}", "00".repeat(32));
    let mut result = AuthorizationResult {
        authorized: false,
        rejection_reason: String::new(),
        gateway_app_id: al.gateway_app_id.clone(),
        current_root_epoch: current.map_or(0, |epoch| epoch.number),
        current_root_epoch_hash: current.map_or_else(zero_hash, |epoch| epoch.hash.clone()),
        latest_root_epoch: latest.map_or(0, |epoch| epoch.number),
        latest_root_epoch_hash: latest.map_or_else(zero_hash, |epoch| epoch.hash.clone()),
        current_app_epoch: if is_kms {
            0
        } else {
            al.app(&request.boot_info.app_id)
                .map_or(0, |app| app.current_app_epoch)
        },
    };
    let info = &request.boot_info;
    // key handover may carry a registered but not yet active epoch, so the
    // keyring can be distributed before activation; key-issuing operations
    // stay on active epochs.
    let handover = matches!(
        request.operation,
        Operation::KmsExportKeys | Operation::KmsImportKeys
    );
    result.rejection_reason = if request.operation.is_kms() != is_kms {
        "invalid authorization operation".into()
    } else if current.is_none() && request.operation != Operation::KmsBootstrap {
        "root epoch not registered".into()
    } else if request
        .requested_root_epoch
        .is_some_and(|epoch| epoch as usize > result.latest_root_epoch)
    {
        "requested root epoch is not registered".into()
    } else if !handover
        && request
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
        result.authorized = policy.is_allowed;
        policy.reason
    };
    Ok(result)
}

fn unavailable(error: anyhow::Error) -> Status {
    rocket::warn!("invalid authorization configuration: {error}");
    Status::ServiceUnavailable
}

/// authorize and log the decision with the identities an operator needs to
/// extend the allowlist (device ID, measurements, TCB status).
fn authorize_logged(
    request: &AuthorizationRequest,
    is_kms: bool,
    config: &PathBuf,
) -> Result<Json<AuthorizationResult>, Status> {
    let result = authorize(request, is_kms, &load(config)).map_err(unavailable)?;
    let info = &request.boot_info;
    rocket::info!(
        "authorize {:?} app={} compose={} mr={} os={} device={} tcb={} advisories={:?} -> authorized={} ({})",
        request.operation,
        norm(&info.app_id),
        norm(&info.compose_hash),
        norm(&info.mr_aggregated),
        norm(&info.os_image_hash),
        norm(&info.device_id),
        info.tcb_status,
        info.advisory_ids,
        result.authorized,
        result.rejection_reason
    );
    Ok(Json(result))
}

#[post("/authorizeApp", data = "<request>")]
fn authorize_app(
    request: Json<AuthorizationRequest>,
    cli: &State<Cli>,
) -> Result<Json<AuthorizationResult>, Status> {
    authorize_logged(&request, false, &cli.config)
}

#[post("/authorizeKms", data = "<request>")]
fn authorize_kms(
    request: Json<AuthorizationRequest>,
    cli: &State<Cli>,
) -> Result<Json<AuthorizationResult>, Status> {
    authorize_logged(&request, true, &cli.config)
}

#[get("/app/<app_id>")]
fn app_epoch(app_id: &str, cli: &State<Cli>) -> Result<Json<serde_json::Value>, Status> {
    let id = norm(app_id);
    if hex::decode(&id).map_or(true, |bytes| bytes.len() != 20) {
        return Err(Status::BadRequest);
    }
    // An unknown app is not epoch zero: its epoch cannot be vouched for.
    let app = load(&cli.config);
    let app = app.app(&id).ok_or(Status::NotFound)?;
    Ok(Json(json!({ "currentAppEpoch": app.current_app_epoch })))
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
        "bootAuth/app app={} compose={} os={} device={} tcb={} -> allowed={} ({})",
        norm(&info.app_id),
        norm(&info.compose_hash),
        norm(&info.os_image_hash),
        norm(&info.device_id),
        info.tcb_status,
        r.is_allowed,
        r.reason
    );
    Json(r)
}

#[post("/bootAuth/kms", data = "<info>")]
fn boot_kms(info: Json<BootInfo>, cli: &State<Cli>) -> Json<BootResponse> {
    let r = check_kms(&info, &load(&cli.config));
    rocket::info!(
        "bootAuth/kms mr={} device={} tcb={} -> allowed={} ({})",
        norm(&info.mr_aggregated),
        norm(&info.device_id),
        info.tcb_status,
        r.is_allowed,
        r.reason
    );
    Json(r)
}

/// info endpoint the KMS GETs to populate its metadata.
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
        "chainId": al.chain_id,
        // `appAuthImplementation` is the older name of `appImplementation`.
        "appAuthImplementation": al.app_implementation,
        "appImplementation": al.app_implementation,
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
            "kms": {"mrAggregated": ["bb"], "allowAnyDevice": true},
            "apps": {"0x2222222222222222222222222222222222222222": {"composeHashes": ["cc"], "allowAnyDevice": true}}
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
        let with_operation = |body: &serde_json::Value, operation: &str| {
            let mut body = body.clone();
            body["operation"] = operation.into();
            body
        };
        for (route, body, allowed) in [
            ("/authorizeKms", kms.clone(), true),
            ("/authorizeApp", app.clone(), true),
            ("/authorizeKms", app.clone(), false),
            ("/authorizeApp", kms.clone(), false),
            // The caller matches the route, but the operation belongs to the other scope.
            ("/authorizeKms", with_operation(&kms, "app_get_key"), false),
            ("/authorizeApp", with_operation(&app, "kms_serve"), false),
        ] {
            let response = client
                .post(route)
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            let response: serde_json::Value = response.into_json().await.unwrap();
            assert_eq!(response["authorized"], allowed);
            assert_eq!(response["currentRootEpoch"], 0);
            assert_eq!(response["currentAppEpoch"], 0);
            assert_eq!(response["latestRootEpoch"], 0);
            assert_eq!(
                response["latestRootEpochHash"],
                response["currentRootEpochHash"]
            );
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
            assert_eq!(response["authorized"], false);
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
        assert_eq!(response["authorized"], false);
        assert_eq!(
            response["currentRootEpochHash"],
            format!("0x{}", "00".repeat(32))
        );
        assert_eq!(response["latestRootEpoch"], 0);
        assert_eq!(
            response["latestRootEpochHash"],
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
                "osImages": ["aa"],
                "apps": {configured_id: {"currentAppEpoch": 2, "composeHashes": ["ee"], "allowAnyDevice": true}}
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
                request["operation"] = "app_get_key".into();
                request["appId"] = id.clone().into();
                request["composeHash"] = "ee".into();
                request["osImageHash"] = "aa".into();
                let response: serde_json::Value = client
                    .post("/authorizeApp")
                    .header(ContentType::JSON)
                    .body(request.to_string())
                    .dispatch()
                    .await
                    .into_json()
                    .await
                    .unwrap();
                assert_eq!(response["authorized"], allowed);
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
        assert_eq!(
            client
                .get(format!("/app/0x{}", "cd".repeat(20)))
                .dispatch()
                .await
                .status(),
            Status::NotFound
        );
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            client.get(format!("/app/0x{id}")).dispatch().await.status(),
            Status::NotFound
        );
    }

    async fn post_json(
        client: &rocket::local::asynchronous::Client,
        route: &str,
        body: &serde_json::Value,
    ) -> serde_json::Value {
        let response = client
            .post(route.to_string())
            .header(rocket::http::ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "{route}");
        response.into_json().await.unwrap()
    }

    async fn client_for(path: &std::path::Path) -> rocket::local::asynchronous::Client {
        rocket::local::asynchronous::Client::tracked(server(Cli {
            config: path.to_path_buf(),
            address: "127.0.0.1".into(),
            port: 0,
        }))
        .await
        .unwrap()
    }

    #[rocket::async_test]
    async fn tcb_status_and_advisories_are_checked_only_when_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        let client = client_for(&path).await;
        let base = json!({
            "kmsContractAddr": "11".repeat(20),
            "rootEpochs": [{"caPubkey": "aa", "k256Pubkey": "bb"}],
            "osImages": ["aa"],
            "kms": {"mrAggregated": ["bb"], "allowAnyDevice": true},
            "apps": {"22".repeat(20): {"composeHashes": ["cc"], "allowAnyDevice": true}}
        });
        let kms = json!({"operation": "kms_serve", "appId": "11".repeat(20), "mrAggregated": "bb", "osImageHash": "aa"});
        let app = json!({"operation": "app_get_key", "appId": "22".repeat(20), "composeHash": "cc", "osImageHash": "aa"});
        let legacy = json!({"appId": "22".repeat(20), "composeHash": "cc", "osImageHash": "aa"});
        let platform =
            |tcb: &str, advisories: &[&str]| json!({"tcbStatus": tcb, "advisoryIds": advisories});
        let cases = [
            // Absent fields: neither the TCB status nor advisories are checked.
            (json!({}), platform("OutOfDate", &["INTEL-SA-00001"]), true),
            (json!({}), platform("", &[]), true),
            (
                json!({"allowedTcbStatuses": ["UpToDate"]}),
                platform("UpToDate", &[]),
                true,
            ),
            (
                json!({"allowedTcbStatuses": ["UpToDate"]}),
                platform("OutOfDate", &[]),
                false,
            ),
            (
                json!({"allowedTcbStatuses": ["UpToDate"]}),
                platform("", &[]),
                false,
            ),
            (
                json!({"allowedTcbStatuses": ["UpToDate", "SWHardeningNeeded"]}),
                platform("SWHardeningNeeded", &[]),
                true,
            ),
            (
                json!({"allowedTcbStatuses": []}),
                platform("UpToDate", &[]),
                false,
            ),
            (
                json!({"allowedAdvisoryIds": []}),
                platform("OutOfDate", &[]),
                true,
            ),
            (
                json!({"allowedAdvisoryIds": []}),
                platform("UpToDate", &["INTEL-SA-00001"]),
                false,
            ),
            (
                json!({"allowedAdvisoryIds": ["INTEL-SA-00001"]}),
                platform("UpToDate", &["INTEL-SA-00001"]),
                true,
            ),
            (
                json!({"allowedAdvisoryIds": ["INTEL-SA-00001"]}),
                platform("UpToDate", &["INTEL-SA-00001", "INTEL-SA-00002"]),
                false,
            ),
        ];
        for (policy_fields, platform, allowed) in cases {
            let mut policy = base.clone();
            policy
                .as_object_mut()
                .unwrap()
                .extend(policy_fields.as_object().unwrap().clone());
            std::fs::write(&path, policy.to_string()).unwrap();
            let with_platform = |body: &serde_json::Value| {
                let mut body = body.clone();
                body.as_object_mut()
                    .unwrap()
                    .extend(platform.as_object().unwrap().clone());
                body
            };
            let context = format!("{policy_fields} {platform}");
            let response = post_json(&client, "/authorizeKms", &with_platform(&kms)).await;
            assert_eq!(response["authorized"], allowed, "kms {context}");
            let response = post_json(&client, "/authorizeApp", &with_platform(&app)).await;
            assert_eq!(response["authorized"], allowed, "app {context}");
            let response = post_json(&client, "/bootAuth/app", &with_platform(&legacy)).await;
            assert_eq!(response["isAllowed"], allowed, "bootAuth/app {context}");
            if !allowed {
                let reason = response["reason"].as_str().unwrap();
                assert!(
                    reason.starts_with("tcb status") || reason.starts_with("advisory"),
                    "{reason}"
                );
            }
        }
    }

    /// A config written for the removed auth-simple server, with every field it
    /// read, keeps loading and authorizing.
    #[rocket::async_test]
    async fn an_auth_simple_config_file_still_authorizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth-config.json");
        let app_id = "0x7a3b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5B";
        let gateway_id = "0x75537828f2ce51be7289709686A69CbFDbB714F1";
        let kms_id = "0x1111111111111111111111111111111111111111";
        let config = json!({
            "gatewayAppId": gateway_id,
            "kmsContractAddr": kms_id,
            "chainId": 2035,
            "appImplementation": "0x3333333333333333333333333333333333333333",
            "osImages": ["0x0B327BCD"],
            "allowedTcbStatuses": ["UpToDate"],
            "allowedAdvisoryIds": [],
            "kms": {"mrAggregated": ["0xAbCd"], "devices": ["0xD1"], "allowAnyDevice": false},
            "apps": {
                app_id: {"currentAppEpoch": 0, "composeHashes": ["0x700A"], "devices": ["0xD2"], "allowAnyDevice": false},
                gateway_id: {"composeHashes": ["0x0123"], "allowAnyDevice": true}
            },
            "rootEpochs": [{"caPubkey": "0xaa", "k256Pubkey": "0xbb"}],
            "currentRootEpoch": 0
        });
        std::fs::write(&path, config.to_string()).unwrap();
        let client = client_for(&path).await;

        let info: serde_json::Value = client.get("/").dispatch().await.into_json().await.unwrap();
        assert_eq!(info["gatewayAppId"], gateway_id);
        assert_eq!(info["kmsContractAddr"], kms_id);
        assert_eq!(info["chainId"], 2035);
        assert_eq!(
            info["appImplementation"],
            "0x3333333333333333333333333333333333333333"
        );
        assert_eq!(info["appAuthImplementation"], info["appImplementation"]);
        assert_eq!(info["rootEpoch"], 0);

        // Hex values match regardless of `0x` prefix and case, as in auth-simple.
        let app = json!({
            "operation": "app_get_key", "appId": app_id.to_lowercase(), "composeHash": "700a",
            "osImageHash": "0b327bcd", "deviceId": "d2", "tcbStatus": "UpToDate", "advisoryIds": []
        });
        let response = post_json(&client, "/authorizeApp", &app).await;
        assert_eq!(response["authorized"], true, "{response}");
        assert_eq!(response["gatewayAppId"], gateway_id);
        let mut other_device = app.clone();
        other_device["deviceId"] = "d1".into();
        let response = post_json(&client, "/authorizeApp", &other_device).await;
        assert_eq!(response["authorized"], false);
        assert_eq!(response["rejectionReason"], "device not allowed");

        let kms = json!({
            "operation": "kms_serve", "appId": kms_id, "mrAggregated": "abcd",
            "deviceId": "0xD1", "tcbStatus": "UpToDate", "advisoryIds": []
        });
        let response = post_json(&client, "/authorizeKms", &kms).await;
        assert_eq!(response["authorized"], true, "{response}");
        let mut legacy = kms.clone();
        legacy.as_object_mut().unwrap().remove("operation");
        legacy["rootEpoch"] = 0.into();
        legacy["rootEpochHash"] = response["currentRootEpochHash"].clone();
        let response = post_json(&client, "/bootAuth/kms", &legacy).await;
        assert_eq!(response["isAllowed"], true, "{response}");
        legacy["tcbStatus"] = "OutOfDate".into();
        let response = post_json(&client, "/bootAuth/kms", &legacy).await;
        assert_eq!(response["isAllowed"], false);
        assert_eq!(response["reason"], "tcb status not allowed");

        let epoch: serde_json::Value = client
            .get(format!(
                "/app/{}",
                app_id.to_uppercase().replacen("0X", "0x", 1)
            ))
            .dispatch()
            .await
            .into_json()
            .await
            .unwrap();
        assert_eq!(epoch["currentAppEpoch"], 0);
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
    fn empty_lists_allow_nothing() {
        let device = |devices: &[&str], allow_any| -> Allowlist {
            let devices: Vec<_> = devices.iter().map(|d| d.to_string()).collect();
            serde_json::from_value(json!({
                "osImages": ["0xIMG"],
                "kms": {"mrAggregated": ["0xMR"], "devices": devices, "allowAnyDevice": allow_any},
                "apps": {"0xApp1": {"composeHashes": ["0xHASH"], "devices": devices, "allowAnyDevice": allow_any}}
            }))
            .unwrap()
        };
        let mut app = boot("0xApp1", "0xHASH", "0xIMG");
        app.device_id = "0xDEV".into();
        let kms = BootInfo {
            mr_aggregated: "0xMR".into(),
            device_id: "0xDEV".into(),
            ..Default::default()
        };
        for al in [device(&[], false), device(&["0xOTHER"], false)] {
            assert_eq!(check_app(&app, &al).reason, "device not allowed");
            assert_eq!(check_kms(&kms, &al).reason, "device not allowed");
        }
        for al in [device(&["0xdev"], false), device(&[], true)] {
            assert!(check_app(&app, &al).is_allowed);
            assert!(check_kms(&kms, &al).is_allowed);
        }
        let mut al = allowlist();
        al.os_images.clear();
        assert_eq!(check_app(&app, &al).reason, "os image allowlist is empty");
    }

    /// The shape `dstack-cli-core` generates (`auth_allowlist_json` plus an app
    /// entry added by `register_app_in_allowlist`) keeps working.
    #[test]
    fn the_generated_default_allowlist_still_allows() {
        let al: Allowlist = serde_json::from_value(json!({
            "osImages": ["0xIMG"],
            "kms": {"mrAggregated": ["0xMR"], "devices": [], "allowAnyDevice": true},
            "apps": {"app1": {"composeHashes": ["hash"], "devices": [], "allowAnyDevice": true}}
        }))
        .unwrap();
        let mut app = boot("0xAPP1", "0xHASH", "img");
        app.device_id = "0xANY".into();
        assert!(check_app(&app, &al).is_allowed);
        let kms = BootInfo {
            mr_aggregated: "0xmr".into(),
            device_id: "0xANY".into(),
            ..Default::default()
        };
        assert!(check_kms(&kms, &al).is_allowed);
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
    fn authorization_reports_the_latest_configured_root_epoch() {
        let al: Allowlist = serde_json::from_value(json!({
            "rootEpochs": [
                {"caPubkey": "aa", "k256Pubkey": "bb"},
                {"caPubkey": "cc", "k256Pubkey": "dd"},
                {"caPubkey": "ee", "k256Pubkey": "ff"}
            ],
            "currentRootEpoch": 1
        }))
        .unwrap();
        let request: AuthorizationRequest =
            serde_json::from_value(json!({"operation": "kms_serve", "appId": "11".repeat(20)}))
                .unwrap();
        let result = authorize(&request, true, &al).unwrap();
        let hashes = dstack_types::root_epoch::chain_hashes([
            (&[0xaa][..], &[0xbb][..]),
            (&[0xcc], &[0xdd]),
            (&[0xee], &[0xff]),
        ]);
        assert_eq!(result.current_root_epoch, 1);
        assert_eq!(
            result.current_root_epoch_hash,
            format!("0x{}", hex::encode(hashes[1]))
        );
        assert_eq!(result.latest_root_epoch, 2);
        assert_eq!(
            result.latest_root_epoch_hash,
            format!("0x{}", hex::encode(hashes[2]))
        );
    }

    #[test]
    fn a_pending_root_epoch_is_authorized_for_kms_key_handover() {
        // epoch 1 is registered (latest) but not current: pending
        let al: Allowlist = serde_json::from_value(json!({
            "kmsContractAddr": "0x1111111111111111111111111111111111111111",
            "kms": {"mrAggregated": ["bb"], "allowAnyDevice": true},
            "rootEpochs": [
                {"caPubkey": "aa", "k256Pubkey": "bb"},
                {"caPubkey": "cc", "k256Pubkey": "dd"}
            ],
            "currentRootEpoch": 0
        }))
        .unwrap();
        let ask = |operation: &str, requested: u32| {
            let request: AuthorizationRequest = serde_json::from_value(json!({
                "operation": operation,
                "appId": "11".repeat(20),
                "mrAggregated": "bb",
                "requestedRootEpoch": requested,
            }))
            .unwrap();
            authorize(&request, true, &al).unwrap()
        };

        let current = ask("kms_export_keys", 0);
        assert!(current.authorized, "{}", current.rejection_reason);
        assert_eq!(current.current_root_epoch, 0);
        assert_eq!(current.latest_root_epoch, 1);

        for operation in ["kms_import_keys", "kms_export_keys"] {
            let pending = ask(operation, 1);
            assert!(
                pending.authorized,
                "{operation} at the pending epoch 1: {}",
                pending.rejection_reason
            );
            assert!(!ask(operation, 2).authorized);
        }

        let serve = ask("kms_serve", 1);
        assert!(!serve.authorized);
        assert_eq!(serve.rejection_reason, "requested root epoch is not active");
    }

    #[test]
    fn allows_only_a_kms_serving_the_current_root_epoch() {
        // Shared with the DstackKms contract tests.
        let h0 = "0x10ab6b6c8e7601901b0f1767985bf40d35bf3129e0866fe12dcc7c8f04a298f2";
        let h1 = "0x50152a82023f2219a31723b476c13bc5f608ab4147946dabdec15d4f3d648ed4";
        let mut al: Allowlist = serde_json::from_str(
            r#"{"kms":{"mrAggregated":["0xMR"],"allowAnyDevice":true},
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
        // A KMS predating root epochs is served only while epoch 0 is current.
        assert!(check_kms(&info(None, ""), &al).is_allowed);

        al.current_root_epoch = 1;
        assert_eq!(info_json(&al).unwrap()["rootEpoch"], 1);
        assert_eq!(info_json(&al).unwrap()["rootEpochHash"], h1);
        assert!(check_kms(&info(Some(1), &h1.to_uppercase()), &al).is_allowed);
        assert!(!check_kms(&info(Some(0), h0), &al).is_allowed);
        assert!(!check_kms(&info(Some(1), h0), &al).is_allowed);
        assert!(!check_kms(&info(None, ""), &al).is_allowed);

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
            "advisoryIds": ["INTEL-SA-00001"]
        }"#;
        let info: BootInfo = serde_json::from_str(wire).expect("kms BootInfo must deserialize");
        assert_eq!(norm(&info.mr_aggregated), "aabb");
        assert_eq!(norm(&info.os_image_hash), "c2aa");
        assert_eq!(norm(&info.app_id), "app1");
        assert_eq!(norm(&info.compose_hash), "hash");
        assert_eq!(norm(&info.device_id), "dev");
        assert_eq!(info.tcb_status, "UpToDate");
        assert_eq!(info.advisory_ids, ["INTEL-SA-00001"]);
        // a check using this payload should pass against a matching allowlist.
        let info2: BootInfo = serde_json::from_str(wire).unwrap();
        let al: Allowlist = serde_json::from_str(
            r#"{"osImages":["0xC2AA"],"apps":{"0xApp1":{"composeHashes":["0xHASH"],"allowAnyDevice":true}}}"#,
        )
        .unwrap();
        assert!(check_app(&info2, &al).is_allowed);
    }
}
