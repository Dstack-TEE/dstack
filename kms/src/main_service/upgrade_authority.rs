// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::AuthApi;
use anyhow::{bail, Context, Result};
use ra_tls::attestation::AttestationMode;
use ra_tls::attestation::VerifiedAttestation;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BootInfo {
    pub attestation_mode: AttestationMode,
    #[serde(with = "hex_bytes")]
    pub mr_aggregated: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub os_image_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mr_system: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub compose_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub instance_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub device_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub key_provider_info: Vec<u8>,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
}

pub(crate) fn build_boot_info(
    att: &VerifiedAttestation,
    use_boottime_mr: bool,
    vm_config_str: &str,
) -> Result<BootInfo> {
    let tcb_status;
    let advisory_ids;
    match att.report.tdx_report() {
        Some(report) => {
            tcb_status = report.status.clone();
            advisory_ids = report.advisory_ids.clone();
        }
        None => {
            tcb_status = "".to_string();
            advisory_ids = Vec::new();
        }
    };
    let app_info = att.decode_app_info_ex(use_boottime_mr, vm_config_str)?;
    Ok(BootInfo {
        attestation_mode: att.quote.mode(),
        mr_aggregated: app_info.mr_aggregated.to_vec(),
        os_image_hash: app_info.os_image_hash,
        mr_system: app_info.mr_system.to_vec(),
        app_id: app_info.app_id,
        compose_hash: app_info.compose_hash,
        instance_id: app_info.instance_id,
        device_id: app_info.device_id,
        key_provider_info: app_info.key_provider_info,
        tcb_status,
        advisory_ids,
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BootResponse {
    pub is_allowed: bool,
    pub gateway_app_id: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthApiInfoResponse {
    pub status: String,
    pub kms_contract_addr: String,
    pub gateway_app_id: String,
    pub chain_id: u64,
    pub app_implementation: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetInfoResponse {
    pub is_dev: bool,
    pub gateway_app_id: Option<String>,
    pub kms_contract_address: Option<String>,
    pub chain_id: Option<u64>,
    pub app_implementation: Option<String>,
}

async fn http_get<R: DeserializeOwned>(url: &str) -> Result<R> {
    send_request(reqwest::Client::new().get(url), url).await
}

async fn http_post<R: DeserializeOwned>(url: &str, body: &impl Serialize) -> Result<R> {
    send_request(reqwest::Client::new().post(url).json(body), url).await
}

async fn send_request<R: DeserializeOwned>(req: reqwest::RequestBuilder, url: &str) -> Result<R> {
    static USER_AGENT: &str = concat!("dstack-kms/", env!("CARGO_PKG_VERSION"));
    let response = req.header("User-Agent", USER_AGENT).send().await?;
    let status = response.status();
    let body = response.text().await?;
    let short_body = &body[..body.len().min(512)];
    if !status.is_success() {
        bail!("auth api {url} returned {status}: {short_body}");
    }
    serde_json::from_str(&body).with_context(|| {
        format!("failed to decode response from {url}, status={status}, body={short_body}")
    })
}

impl AuthApi {
    pub async fn is_app_allowed(&self, boot_info: &BootInfo, is_kms: bool) -> Result<BootResponse> {
        match self {
            AuthApi::Dev { dev } => Ok(BootResponse {
                is_allowed: true,
                reason: "".to_string(),
                gateway_app_id: dev.gateway_app_id.clone(),
            }),
            AuthApi::Webhook { webhook } => {
                let path = if is_kms {
                    "bootAuth/kms"
                } else {
                    "bootAuth/app"
                };
                let url = url_join(&webhook.url, path);
                http_post(&url, &boot_info).await
            }
        }
    }

    pub async fn get_info(&self) -> Result<GetInfoResponse> {
        match self {
            AuthApi::Dev { dev } => Ok(GetInfoResponse {
                is_dev: true,
                kms_contract_address: None,
                gateway_app_id: Some(dev.gateway_app_id.clone()),
                chain_id: None,
                app_implementation: None,
            }),
            AuthApi::Webhook { webhook } => {
                let info: AuthApiInfoResponse = http_get(&webhook.url).await?;
                Ok(GetInfoResponse {
                    is_dev: false,
                    kms_contract_address: Some(info.kms_contract_addr.clone()),
                    chain_id: Some(info.chain_id),
                    gateway_app_id: Some(info.gateway_app_id.clone()),
                    app_implementation: Some(info.app_implementation.clone()),
                })
            }
        }
    }
}

fn url_join(url: &str, path: &str) -> String {
    let mut url = url.to_string();
    if !url.ends_with('/') {
        url.push('/');
    }
    url.push_str(path);
    url
}
