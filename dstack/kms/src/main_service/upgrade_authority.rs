// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::build_boot_info_for_attestation;
use crate::config::{AuthApi, KmsConfig};
use anyhow::{bail, Context, Result};
use dstack_guest_agent_rpc::v0::{
    dstack_guest_client::DstackGuestClient, AttestResponse, RawQuoteArgs,
};
use http_client::prpc::PrpcClient;
use ra_tls::attestation::{AttestationVerifier, VerifiedAttestation, VersionedAttestation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The KMS `bootAuth` payload. This is the verifier's `PolicyBootInfo` — the one
/// canonical struct shared by the producer (KMS) and the policy input the
/// verifier advertises — so the two cannot drift a field or an encoding apart.
pub(crate) use dstack_verifier::PolicyBootInfo as BootInfo;

pub(crate) fn build_boot_info(
    att: &VerifiedAttestation,
    use_boottime_mr: bool,
    vm_config_str: &str,
) -> Result<BootInfo> {
    let variant = att.quote.variant();
    let (tcb_status, advisory_ids) = dstack_verifier::policy_tcb_fields(att);
    let app_info = att.decode_app_info_ex(use_boottime_mr, vm_config_str)?;
    ensure_app_id_len(&app_info.app_id)?;
    Ok(BootInfo {
        tee_variant: variant,
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

pub(crate) fn ensure_app_id_len(app_id: &[u8]) -> Result<()> {
    if app_id.len() != 20 {
        bail!("app_id must be 20 bytes");
    }
    Ok(())
}

pub(crate) async fn local_kms_boot_info(verifier: &AttestationVerifier) -> Result<BootInfo> {
    let response = app_attest(pad64([0u8; 32]))
        .await
        .context("Failed to get local KMS attestation")?;
    let attestation = VersionedAttestation::from_bytes(&response.attestation)
        .context("Failed to decode local KMS attestation")?;
    let verified = attestation
        .into_v1()
        .verify(verifier)
        .await
        .context("Failed to verify local KMS attestation")?;
    build_boot_info_for_attestation(&verified, false, "")
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
    #[serde(default)]
    pub eth_rpc_url: String,
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
    pub eth_rpc_url: Option<String>,
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
                eth_rpc_url: None,
                gateway_app_id: Some(dev.gateway_app_id.clone()),
                chain_id: None,
                app_implementation: None,
            }),
            AuthApi::Webhook { webhook } => {
                let info: AuthApiInfoResponse = http_get(&webhook.url).await?;
                let eth_rpc_url = if info.eth_rpc_url.is_empty() {
                    None
                } else {
                    Some(info.eth_rpc_url.clone())
                };
                Ok(GetInfoResponse {
                    is_dev: false,
                    kms_contract_address: Some(info.kms_contract_addr.clone()),
                    eth_rpc_url,
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

pub(crate) fn dstack_client() -> DstackGuestClient<PrpcClient> {
    let address = dstack_types::dstack_agent_address();
    let http_client = PrpcClient::new(address);
    DstackGuestClient::new(http_client)
}

pub(crate) async fn app_attest(report_data: Vec<u8>) -> Result<AttestResponse> {
    dstack_client().attest(RawQuoteArgs { report_data }).await
}

pub(crate) fn pad64(hash: [u8; 32]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(64);
    padded.extend_from_slice(&hash);
    padded.resize(64, 0);
    padded
}

pub(crate) async fn ensure_self_kms_allowed(
    cfg: &KmsConfig,
    verifier: &AttestationVerifier,
) -> Result<()> {
    if !cfg.enforce_self_authorization {
        return Ok(());
    }
    let boot_info = local_kms_boot_info(verifier)
        .await
        .context("failed to build local KMS boot info")?;
    let response = cfg
        .auth_api
        .is_app_allowed(&boot_info, true)
        .await
        .context("failed to call KMS auth check")?;
    if !response.is_allowed {
        bail!("boot denied: {}", response.reason);
    }
    Ok(())
}

pub(crate) async fn ensure_kms_allowed(
    cfg: &KmsConfig,
    attestation: &VerifiedAttestation,
    verifier: &AttestationVerifier,
) -> Result<()> {
    let mut boot_info = build_boot_info_for_attestation(attestation, false, "")
        .context("failed to build KMS boot info from attestation")?;
    // Workaround: old source KMS instances use the legacy cert format (separate TDX_QUOTE +
    // EVENT_LOG OIDs) which lacks vm_config, resulting in an empty os_image_hash.
    // Fill it from the local KMS's own value. This is safe because mrAggregated already
    // validates OS image integrity transitively through the RTMR measurement chain.
    // TODO: remove once all source KMS instances use the unified PHALA_RATLS_ATTESTATION format.
    if boot_info.os_image_hash.is_empty() {
        let local_info = local_kms_boot_info(verifier)
            .await
            .context("failed to get local KMS boot info for os_image_hash fallback")?;
        boot_info.os_image_hash = local_info.os_image_hash;
    }
    let response = cfg
        .auth_api
        .is_app_allowed(&boot_info, true)
        .await
        .context("failed to call KMS auth check")?;
    if !response.is_allowed {
        bail!("boot denied: {}", response.reason);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Webhook;
    use ra_tls::attestation::TeeVariant;
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn boot_info(identity: u8) -> BootInfo {
        BootInfo {
            tee_variant: TeeVariant::DstackTdx,
            mr_aggregated: vec![identity; 32],
            os_image_hash: vec![identity.wrapping_add(1); 32],
            mr_system: vec![identity.wrapping_add(2); 32],
            app_id: vec![identity.wrapping_add(3); 20],
            compose_hash: vec![identity.wrapping_add(4); 32],
            instance_id: vec![identity.wrapping_add(5); 20],
            device_id: vec![identity.wrapping_add(6); 32],
            key_provider_info: vec![identity.wrapping_add(7); 32],
            tcb_status: "UpToDate".into(),
            advisory_ids: vec![],
        }
    }

    fn serve(responses: Vec<&'static str>) -> (String, thread::JoinHandle<Vec<(String, Value)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let read = stream.read(&mut chunk).unwrap();
                    assert_ne!(read, 0, "request ended before headers");
                    request.extend_from_slice(&chunk[..read]);
                    if let Some(position) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]).into_owned();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                    })
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let read = stream.read(&mut chunk).unwrap();
                    assert_ne!(read, 0, "request ended before body");
                    request.extend_from_slice(&chunk[..read]);
                }
                let path = headers
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string();
                let body =
                    serde_json::from_slice(&request[header_end..header_end + content_length])
                        .unwrap();
                requests.push((path, body));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
            }
            requests
        });
        (format!("http://{address}"), handle)
    }

    fn webhook(url: String) -> AuthApi {
        AuthApi::Webhook {
            webhook: Webhook { url },
        }
    }

    #[test]
    fn app_id_len_must_be_20_bytes() {
        assert!(ensure_app_id_len(&[0u8; 20]).is_ok());

        match ensure_app_id_len(&[0u8; 19]) {
            Ok(()) => panic!("19-byte app_id must reject"),
            Err(err) => assert!(err.to_string().contains("app_id must be 20 bytes")),
        }
    }

    #[rocket::async_test]
    async fn repeated_authorization_is_never_served_from_a_decision_cache() {
        let (url, server) = serve(vec![
            r#"{"isAllowed":true,"gatewayAppId":"gateway","reason":"initial allow"}"#,
            r#"{"isAllowed":false,"gatewayAppId":"gateway","reason":"revoked"}"#,
        ]);
        let auth = webhook(url);
        let info = boot_info(1);

        let first = auth.is_app_allowed(&info, false).await.unwrap();
        let repeated = auth.is_app_allowed(&info, false).await.unwrap();
        assert!(first.is_allowed);
        assert!(!repeated.is_allowed);
        assert_eq!(repeated.reason, "revoked");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].0, "/bootAuth/app");
        assert_eq!(requests[1].0, "/bootAuth/app");
        assert_eq!(requests[0].1, requests[1].1);
    }

    #[rocket::async_test]
    async fn authorization_scope_preserves_route_and_every_identity_field() {
        let (url, server) = serve(vec![
            r#"{"isAllowed":true,"gatewayAppId":"gateway","reason":"app"}"#,
            r#"{"isAllowed":true,"gatewayAppId":"gateway","reason":"kms"}"#,
        ]);
        let auth = webhook(url);
        let app = boot_info(10);
        let kms = boot_info(20);

        assert!(auth.is_app_allowed(&app, false).await.unwrap().is_allowed);
        assert!(auth.is_app_allowed(&kms, true).await.unwrap().is_allowed);

        let requests = server.join().unwrap();
        assert_eq!(requests[0].0, "/bootAuth/app");
        assert_eq!(requests[1].0, "/bootAuth/kms");
        assert_ne!(requests[0].1["appId"], requests[1].1["appId"]);
        assert_ne!(requests[0].1["deviceId"], requests[1].1["deviceId"]);
        assert_ne!(requests[0].1["osImageHash"], requests[1].1["osImageHash"]);
        assert_ne!(requests[0].1["composeHash"], requests[1].1["composeHash"]);
        assert_ne!(requests[0].1["instanceId"], requests[1].1["instanceId"]);
        assert_ne!(requests[0].1["mrAggregated"], requests[1].1["mrAggregated"]);
    }

    #[rocket::async_test]
    async fn malformed_backend_response_fails_closed_and_next_request_recovers() {
        let (url, server) = serve(vec![
            "not-json",
            r#"{"isAllowed":true,"gatewayAppId":"gateway","reason":"recovered"}"#,
        ]);
        let auth = webhook(url);
        let info = boot_info(30);

        let error = auth.is_app_allowed(&info, false).await.unwrap_err();
        assert!(error.to_string().contains("failed to decode response"));
        let recovered = auth.is_app_allowed(&info, false).await.unwrap();
        assert!(recovered.is_allowed);
        assert_eq!(recovered.reason, "recovered");
        assert_eq!(server.join().unwrap().len(), 2);
    }
}
