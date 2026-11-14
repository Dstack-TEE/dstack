// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::build_boot_info_for_attestation;
use crate::config::{AuthApi, KmsConfig};
use anyhow::{bail, Context, Result};
use dstack_guest_agent_rpc::v0::{
    dstack_guest_client::DstackGuestClient, AttestResponse, RawQuoteArgs,
};
pub(crate) use dstack_types::authorization::AuthorizationOperation as Operation;
use http_client::prpc::PrpcClient;
use ra_tls::attestation::{AttestationVerifier, VerifiedAttestation, VersionedAttestation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;

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

/// The hex `launchTicketHash` of a presented ticket.
fn launch_ticket_hash(operation: Operation, ticket: &str) -> Result<String> {
    dstack_types::authorization::check_launch_ticket(ticket).map_err(anyhow::Error::msg)?;
    Ok(hex::encode(operation.launch_ticket_hash(ticket)))
}

pub(crate) fn ensure_app_id_len(app_id: &[u8]) -> Result<()> {
    if app_id.len() != 20 {
        bail!("app_id must be 20 bytes");
    }
    Ok(())
}

/// Policy backends left-pad short hex values, so a short field would alias a
/// whitelisted full-width one.
fn ensure_identity_widths(boot_info: &BootInfo) -> Result<()> {
    ensure_app_id_len(&boot_info.app_id)?;
    if boot_info.compose_hash.len() != 32 {
        bail!("compose_hash must be 32 bytes");
    }
    if !matches!(boot_info.instance_id.len(), 0 | 20) {
        bail!("instance_id must be 20 bytes or empty");
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

#[cfg(test)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BootResponse {
    pub is_allowed: bool,
    pub gateway_app_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthorizationResult {
    pub authorized: bool,
    pub rejection_reason: String,
    pub gateway_app_id: String,
    pub current_root_epoch: u32,
    pub current_app_epoch: u32,
    pub current_root_epoch_hash: String,
    pub latest_root_epoch: u32,
    pub latest_root_epoch_hash: String,
}

impl AuthorizationResult {
    pub fn current_root(&self) -> Result<Option<CurrentRootEpoch>> {
        root_epoch(self.current_root_epoch, &self.current_root_epoch_hash)
    }

    /// The latest registered root epoch, which may be pending activation.
    pub fn latest_root(&self) -> Result<Option<CurrentRootEpoch>> {
        root_epoch(self.latest_root_epoch, &self.latest_root_epoch_hash)
    }
}

/// A zero chain hash means no epoch is registered.
fn root_epoch(epoch: u32, hash: &str) -> Result<Option<CurrentRootEpoch>> {
    let chain_hash: [u8; 32] = hex::decode(hash.trim_start_matches("0x"))
        .ok()
        .and_then(|hash| hash.try_into().ok())
        .context("invalid authorization root epoch chain hash")?;
    if chain_hash == [0; 32] {
        return Ok(None);
    }
    Ok(Some(CurrentRootEpoch { epoch, chain_hash }))
}

/// The root epoch fields: the KMS sends the epoch it serves in boot checks,
/// and auth backends report the current one in info responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RootEpochFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_epoch: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_epoch_hash: Option<String>,
}

impl From<CurrentRootEpoch> for RootEpochFields {
    fn from(current: CurrentRootEpoch) -> Self {
        Self {
            root_epoch: Some(current.epoch),
            root_epoch_hash: Some(format!("0x{}", hex::encode(current.chain_hash))),
        }
    }
}

impl RootEpochFields {
    pub fn registry(&self) -> Result<RootEpochRegistry> {
        match (self.root_epoch, &self.root_epoch_hash) {
            (None, None) => Ok(RootEpochRegistry::Empty),
            (Some(epoch), Some(hash)) => {
                let chain_hash = hex::decode(hash.trim_start_matches("0x"))
                    .ok()
                    .and_then(|hash| hash.try_into().ok())
                    .context("invalid root epoch chain hash")?;
                Ok(RootEpochRegistry::Current(CurrentRootEpoch {
                    epoch,
                    chain_hash,
                }))
            }
            _ => bail!("the auth API reports a root epoch without its chain hash"),
        }
    }
}

/// A root epoch governance registered, with the chain hash committing to the
/// root public keys of epochs 0..=epoch. Usually the current epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CurrentRootEpoch {
    pub epoch: u32,
    pub chain_hash: [u8; 32],
}

/// What governance says about root epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RootEpochRegistry {
    /// The dev backend: there is nothing to check against.
    Unchecked,
    /// No epoch is registered, or the backend predates root epochs.
    Empty,
    Current(CurrentRootEpoch),
}

/// What governance says about root epochs at a key handover: the current epoch
/// and the latest registered one. Chain hashes are cumulative, so the latest
/// binds every registered epoch, including those pending activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootEpochRegistration {
    pub registry: RootEpochRegistry,
    /// Absent for the dev backend and when nothing is registered.
    pub latest: Option<CurrentRootEpoch>,
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
    #[serde(flatten)]
    pub root_epoch: RootEpochFields,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetInfoResponse {
    pub is_dev: bool,
    pub gateway_app_id: Option<String>,
    pub kms_contract_address: Option<String>,
    pub eth_rpc_url: Option<String>,
    pub chain_id: Option<u64>,
    pub app_implementation: Option<String>,
    pub root_epochs: RootEpochRegistry,
}

const AUTH_API_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared so auth API calls reuse pooled connections instead of reconnecting per decision.
fn auth_api_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(AUTH_API_CONNECT_TIMEOUT)
            .build()
            .unwrap_or_default()
    })
}

async fn http_get<R: DeserializeOwned>(url: &str, timeout: Duration) -> Result<R> {
    send_request(auth_api_client().get(url).timeout(timeout), url).await
}

async fn http_post<R: DeserializeOwned>(
    url: &str,
    body: &impl Serialize,
    timeout: Duration,
) -> Result<R> {
    send_request(auth_api_client().post(url).json(body).timeout(timeout), url).await
}

/// Longest stretch of an auth-backend response quoted back in an error.
///
/// #525's convention: include the body so a misconfigured backend is
/// diagnosable, bounded so an HTML error page cannot flood the logs.
const MAX_QUOTED_BODY_BYTES: usize = 512;

/// Take at most [`MAX_QUOTED_BODY_BYTES`] of `body`, ending on a character boundary.
///
/// Slicing a `String` at a fixed byte index panics when that index lands inside a
/// multi-byte character, and this body is whatever the auth backend sent -- a proxy's
/// error page, or a `reason` string an app owner controls through their `DstackApp`
/// contract. Release binaries build with `panic = "abort"`, so that is the KMS process
/// dying on the boot-authorization path rather than one call failing. Rounding the
/// bound down to a boundary keeps it a byte bound, not a character count.
fn quoted_body(body: &str) -> &str {
    &body[..body.floor_char_boundary(MAX_QUOTED_BODY_BYTES)]
}

async fn send_request<R: DeserializeOwned>(req: reqwest::RequestBuilder, url: &str) -> Result<R> {
    static USER_AGENT: &str = concat!("dstack-kms/", env!("CARGO_PKG_VERSION"));
    let response = req.header("User-Agent", USER_AGENT).send().await?;
    let status = response.status();
    let body = response.text().await?;
    let short_body = quoted_body(&body);
    if !status.is_success() {
        bail!("auth api {url} returned {status}: {short_body}");
    }
    serde_json::from_str(&body).with_context(|| {
        format!("failed to decode response from {url}, status={status}, body={short_body}")
    })
}

impl AuthApi {
    pub async fn authorize_kms(
        &self,
        app_info: &BootInfo,
        operation: Operation,
        requested_root_epoch: Option<u32>,
        launch_ticket: &str,
    ) -> Result<AuthorizationResult> {
        if !operation.is_kms() {
            bail!("invalid KMS authorization operation");
        }
        self.check_authorization(
            app_info,
            "authorizeKms",
            operation,
            requested_root_epoch,
            None,
            launch_ticket,
        )
        .await
    }

    pub async fn authorize_app(
        &self,
        app_info: &BootInfo,
        operation: Operation,
        requested_root_epoch: Option<u32>,
        requested_app_epoch: Option<u32>,
        launch_ticket: &str,
    ) -> Result<AuthorizationResult> {
        if operation.is_kms() {
            bail!("invalid app authorization operation");
        }
        self.check_authorization(
            app_info,
            "authorizeApp",
            operation,
            requested_root_epoch,
            requested_app_epoch,
            launch_ticket,
        )
        .await
    }

    async fn check_authorization(
        &self,
        app_info: &BootInfo,
        method: &str,
        operation: Operation,
        requested_root_epoch: Option<u32>,
        requested_app_epoch: Option<u32>,
        launch_ticket: &str,
    ) -> Result<AuthorizationResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct AuthorizationRequest<'a> {
            #[serde(flatten)]
            app_info: &'a BootInfo,
            operation: Operation,
            #[serde(skip_serializing_if = "Option::is_none")]
            requested_app_epoch: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            requested_root_epoch: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            launch_ticket_hash: Option<String>,
        }
        ensure_identity_widths(app_info)?;
        // An empty ticket is none.
        let launch_ticket_hash = (!launch_ticket.is_empty())
            .then(|| launch_ticket_hash(operation, launch_ticket))
            .transpose()?;
        match self {
            AuthApi::Dev { dev } => Ok(AuthorizationResult {
                authorized: true,
                rejection_reason: String::new(),
                gateway_app_id: dev.gateway_app_id.clone(),
                current_root_epoch: 0,
                current_app_epoch: 0,
                current_root_epoch_hash: hex::encode([0; 32]),
                latest_root_epoch: 0,
                latest_root_epoch_hash: hex::encode([0; 32]),
            }),
            AuthApi::Webhook { webhook } => {
                let url = url_join(&webhook.url, method);
                http_post(
                    &url,
                    &AuthorizationRequest {
                        app_info,
                        operation,
                        requested_app_epoch,
                        requested_root_epoch,
                        launch_ticket_hash,
                    },
                    webhook.timeout,
                )
                .await
            }
        }
    }

    pub async fn app_epoch(&self, app_id: &[u8]) -> Result<u32> {
        ensure_app_id_len(app_id)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct AppEpoch {
            current_app_epoch: u32,
        }
        match self {
            AuthApi::Dev { .. } => Ok(0),
            AuthApi::Webhook { webhook } => {
                let url = url_join(&webhook.url, &format!("app/0x{}", hex::encode(app_id)));
                let response: AppEpoch = http_get(&url, webhook.timeout).await?;
                Ok(response.current_app_epoch)
            }
        }
    }

    #[cfg(test)]
    pub async fn is_app_allowed(
        &self,
        boot_info: &BootInfo,
        is_kms: bool,
        root_epoch: Option<CurrentRootEpoch>,
    ) -> Result<BootResponse> {
        #[derive(Serialize)]
        struct BootAuthRequest<'a> {
            #[serde(flatten)]
            boot_info: &'a BootInfo,
            #[serde(flatten)]
            root_epoch: RootEpochFields,
        }

        ensure_identity_widths(boot_info)?;
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
                let request = BootAuthRequest {
                    boot_info,
                    root_epoch: root_epoch.map(Into::into).unwrap_or_default(),
                };
                http_post(&url, &request, webhook.timeout).await
            }
        }
    }

    /// The root CA public key (SPKI DER) of the current root epoch, which
    /// signs the RPC certificate of every KMS serving it; `None` in dev mode,
    /// which registers none.
    pub async fn root_ca_pubkey(&self) -> Result<Option<Vec<u8>>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Info {
            root_ca_pubkey: Option<String>,
        }
        let AuthApi::Webhook { webhook } = self else {
            return Ok(None);
        };
        let info: Info = http_get(&webhook.url, webhook.timeout).await?;
        let key = info.root_ca_pubkey.context(
            "the auth API reports no root CA key: register a root epoch, or upgrade the auth API",
        )?;
        let key =
            hex::decode(key.trim_start_matches("0x")).context("invalid root CA public key")?;
        Ok(Some(key))
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
                root_epochs: RootEpochRegistry::Unchecked,
            }),
            AuthApi::Webhook { webhook } => {
                let info: AuthApiInfoResponse = http_get(&webhook.url, webhook.timeout).await?;
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
                    root_epochs: info.root_epoch.registry()?,
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
        .authorize_kms(&boot_info, Operation::KmsBootstrap, None, "")
        .await
        .context("failed to call KMS bootstrap authorization")?;
    if !response.authorized {
        bail!("boot denied: {}", response.rejection_reason);
    }
    Ok(())
}

/// A source must present its OS image hash. KMS releases before 0.6 issue
/// certificates without a vm_config, and so without one; they cannot be joined
/// directly. Upgrade such a cluster to 0.6 first.
fn ensure_source_os_image(boot_info: &BootInfo) -> Result<()> {
    if boot_info.os_image_hash.is_empty() {
        bail!("the source KMS certificate does not carry its OS image hash; onboard from a v0.6+ source");
    }
    Ok(())
}

pub(crate) async fn ensure_kms_allowed(
    cfg: &KmsConfig,
    attestation: &VerifiedAttestation,
    root_epoch: u32,
) -> Result<RootEpochRegistration> {
    let boot_info = build_boot_info_for_attestation(attestation, false, "")
        .context("failed to build KMS boot info from attestation")?;
    ensure_source_os_image(&boot_info)?;
    let response = cfg
        .auth_api
        .authorize_kms(&boot_info, Operation::KmsExportKeys, Some(root_epoch), "")
        .await
        .context("failed to authorize source KMS key export")?;
    if !response.authorized {
        bail!("boot denied: {}", response.rejection_reason);
    }
    if cfg.auth_api.is_dev() {
        return Ok(RootEpochRegistration {
            registry: RootEpochRegistry::Unchecked,
            latest: None,
        });
    }
    let current = response
        .current_root()?
        .context("root epoch not registered")?;
    let latest = response
        .latest_root()?
        .filter(|latest| latest.epoch >= current.epoch)
        .context("the auth API reports no latest root epoch at or after the current one")?;
    Ok(RootEpochRegistration {
        registry: RootEpochRegistry::Current(current),
        latest: Some(latest),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::Webhook;
    use ra_tls::attestation::TeeVariant;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    pub(crate) fn boot_info(identity: u8) -> BootInfo {
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

    pub(crate) fn serve<S: Into<String>>(
        responses: Vec<S>,
    ) -> (String, thread::JoinHandle<Vec<(String, Value)>>) {
        serve_with_status(responses.into_iter().map(|body| (200, body)).collect())
    }

    /// Like [`serve`], answering each request with its own HTTP status.
    pub(crate) fn serve_with_status<S: Into<String>>(
        responses: Vec<(u16, S)>,
    ) -> (String, thread::JoinHandle<Vec<(String, Value)>>) {
        let responses: Vec<(u16, String)> = responses
            .into_iter()
            .map(|(status, body)| (status, body.into()))
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, response) in responses {
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
                let body = &request[header_end..header_end + content_length];
                let body = if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(body).unwrap()
                };
                requests.push((path, body));
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
            }
            requests
        });
        (format!("http://{address}"), handle)
    }

    /// Joins and rotations share this check, so both refuse such a source.
    #[test]
    fn a_source_certificate_without_an_os_image_hash_is_refused() {
        let legacy = BootInfo {
            os_image_hash: vec![],
            ..boot_info(1)
        };
        let err = ensure_source_os_image(&legacy).unwrap_err();
        assert!(
            err.to_string().contains("onboard from a v0.6+ source"),
            "{err:#}"
        );
        ensure_source_os_image(&boot_info(1)).unwrap();
    }

    pub(crate) fn webhook(url: String) -> AuthApi {
        AuthApi::Webhook {
            webhook: Webhook {
                url,
                timeout: std::time::Duration::from_millis(500),
            },
        }
    }

    /// `GetMeta` reaches the auth API unauthenticated, so a silent backend must not hold it open.
    #[rocket::async_test]
    async fn a_backend_that_never_answers_does_not_hold_the_request_open() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let _blackhole = thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(1).collect();
            thread::sleep(std::time::Duration::from_secs(30));
            drop(held);
        });

        let auth = webhook(format!("http://{address}"));
        let outcome =
            tokio::time::timeout(std::time::Duration::from_secs(10), auth.get_info()).await;

        assert!(
            outcome.is_ok(),
            "the auth API call was still running after 10s"
        );
        let error = outcome.unwrap().expect_err("a silent backend must fail");
        assert!(
            format!("{error:#}").contains("timed out") || format!("{error:#}").contains("timeout"),
            "unexpected error: {error:#}"
        );
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
    async fn short_identities_are_refused_before_they_reach_the_backend() {
        let (url, server) = serve(vec![
            r#"{"isAllowed":true,"gatewayAppId":"gateway","reason":"well-formed"}"#,
        ]);
        let auth = webhook(url);

        let mut aliasing_compose_hash = boot_info(1);
        aliasing_compose_hash.compose_hash.truncate(31);
        let err = auth
            .is_app_allowed(&aliasing_compose_hash, false, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("compose_hash must be 32 bytes"));

        let mut aliasing_instance_id = boot_info(1);
        aliasing_instance_id.instance_id.truncate(19);
        let err = auth
            .is_app_allowed(&aliasing_instance_id, false, None)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("instance_id must be 20 bytes or empty"));

        // `--no-instance-id` deployments carry no instance id.
        let mut no_instance_id = boot_info(1);
        no_instance_id.instance_id.clear();
        assert!(
            auth.is_app_allowed(&no_instance_id, false, None)
                .await
                .unwrap()
                .is_allowed
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[rocket::async_test]
    async fn repeated_authorization_is_never_served_from_a_decision_cache() {
        let (url, server) = serve(vec![
            r#"{"isAllowed":true,"gatewayAppId":"gateway","reason":"initial allow"}"#,
            r#"{"isAllowed":false,"gatewayAppId":"gateway","reason":"revoked"}"#,
        ]);
        let auth = webhook(url);
        let info = boot_info(1);

        let first = auth.is_app_allowed(&info, false, None).await.unwrap();
        let repeated = auth.is_app_allowed(&info, false, None).await.unwrap();
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

        assert!(
            auth.is_app_allowed(&app, false, None)
                .await
                .unwrap()
                .is_allowed
        );
        assert!(
            auth.is_app_allowed(&kms, true, None)
                .await
                .unwrap()
                .is_allowed
        );

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
    async fn authorization_operations_are_typed_and_sent_without_legacy_fallback() {
        let operations = [
            Operation::KmsBootstrap,
            Operation::KmsServe,
            Operation::KmsExportKeys,
            Operation::KmsImportKeys,
            Operation::AppGetKey,
            Operation::AppGetCert,
        ];
        let response = r#"{"authorized":true,"rejectionReason":"","gatewayAppId":"","currentRootEpoch":0,"currentAppEpoch":0,"currentRootEpochHash":"0000000000000000000000000000000000000000000000000000000000000000","latestRootEpoch":0,"latestRootEpochHash":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let (url, server) = serve(vec![response; operations.len()]);
        let auth = webhook(url);
        for operation in operations {
            if operation.is_kms() {
                auth.authorize_kms(&boot_info(1), operation, Some(0), "")
                    .await
                    .unwrap();
            } else {
                auth.authorize_app(&boot_info(1), operation, None, None, "")
                    .await
                    .unwrap();
            }
        }
        let wire_names = [
            "kms_bootstrap",
            "kms_serve",
            "kms_export_keys",
            "kms_import_keys",
            "app_get_key",
            "app_get_cert",
        ];
        for (((route, body), operation), name) in server
            .join()
            .unwrap()
            .into_iter()
            .zip(operations)
            .zip(wire_names)
        {
            assert_eq!(body["operation"], name);
            assert_eq!(
                route,
                if operation.is_kms() {
                    "/authorizeKms"
                } else {
                    "/authorizeApp"
                }
            );
            assert_eq!(
                serde_json::from_value::<Operation>(body["operation"].clone()).unwrap(),
                operation
            );
        }
        assert!(serde_json::from_str::<Operation>(r#""unknown""#).is_err());
    }

    #[rocket::async_test]
    async fn onboarding_pins_the_registered_root_ca_keys() {
        let (url, server) = serve(vec![r#"{"rootCaPubkey":"0x3059"}"#, r#"{"status":"ok"}"#]);
        let auth = webhook(url);
        assert_eq!(auth.root_ca_pubkey().await.unwrap(), Some(vec![0x30, 0x59]));
        // Nothing to pin fails closed: a registry without roots and an auth
        // API that predates the field both omit it.
        assert!(auth.root_ca_pubkey().await.is_err());
        server.join().unwrap();
        let dev = AuthApi::Dev {
            dev: crate::config::Dev {
                gateway_app_id: String::new(),
            },
        };
        assert_eq!(dev.root_ca_pubkey().await.unwrap(), None);
    }

    #[rocket::async_test]
    async fn launch_tickets_are_sent_as_domain_separated_hashes() {
        let response = r#"{"authorized":true,"rejectionReason":"","gatewayAppId":"","currentRootEpoch":0,"currentAppEpoch":0,"currentRootEpochHash":"0000000000000000000000000000000000000000000000000000000000000000","latestRootEpoch":0,"latestRootEpochHash":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let (url, server) = serve(vec![response; 3]);
        let auth = webhook(url);
        let ticket = "t".repeat(32);
        let info = boot_info(1);
        auth.authorize_app(&info, Operation::AppGetKey, None, None, &ticket)
            .await
            .unwrap();
        auth.authorize_kms(&info, Operation::KmsImportKeys, Some(0), &ticket)
            .await
            .unwrap();
        auth.authorize_app(&info, Operation::AppGetCert, None, None, "")
            .await
            .unwrap();
        // A short ticket is refused before it reaches the backend.
        let err = auth
            .authorize_app(&info, Operation::AppGetKey, None, None, "short")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("32 to 1024 bytes"), "{err:#}");

        let requests = server.join().unwrap();
        let sent = |i: usize| requests[i].1.get("launchTicketHash").cloned();
        let expected =
            |domain: &str| Some(hex::encode(Sha256::digest(format!("{domain}{ticket}"))).into());
        assert_eq!(sent(0), expected("dstack-launch-ticket/v1:"));
        assert_eq!(sent(1), expected("dstack-kms-launch-ticket/v1:"));
        assert_eq!(sent(2), None);
    }

    #[rocket::async_test]
    async fn authorization_returns_the_epoch_with_each_decision() {
        let response = |allowed: bool, epoch: u32| {
            format!(
                r#"{{"authorized":{allowed},"rejectionReason":"","gatewayAppId":"gw", "currentRootEpoch":{epoch},"currentAppEpoch":0,"currentRootEpochHash":"0x{}","latestRootEpoch":{latest},"latestRootEpochHash":"0x{}"}}"#,
                "11".repeat(32),
                "22".repeat(32),
                latest = epoch + 1,
            )
        };
        let (url, server) = serve(vec![
            response(true, 0),
            response(false, 1),
            response(true, 1),
            response(true, 1),
            response(false, 1),
        ]);
        let auth = webhook(url);
        let info = boot_info(50);
        let first = auth
            .authorize_app(&info, Operation::AppGetKey, None, None, "")
            .await
            .unwrap();
        let second = auth
            .authorize_app(&info, Operation::AppGetKey, None, None, "")
            .await
            .unwrap();
        assert!(first.authorized);
        assert!(!second.authorized);
        assert_eq!(first.current_root().unwrap().unwrap().epoch, 0);
        assert_eq!(second.current_root().unwrap().unwrap().epoch, 1);
        let latest = second.latest_root().unwrap().unwrap();
        assert_eq!((latest.epoch, latest.chain_hash), (2, [0x22; 32]));
        auth.authorize_app(&info, Operation::AppGetKey, Some(0), Some(0), "")
            .await
            .unwrap();
        auth.authorize_kms(&info, Operation::KmsServe, None, "")
            .await
            .unwrap();
        assert!(
            !auth
                .authorize_kms(&info, Operation::KmsImportKeys, Some(2), "")
                .await
                .unwrap()
                .authorized
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 5);
        assert!(requests[..3]
            .iter()
            .all(|(path, _)| path == "/authorizeApp"));
        assert_eq!(requests[3].0, "/authorizeKms");
        assert_eq!(requests[4].0, "/authorizeKms");
        assert_eq!(requests[4].1["requestedRootEpoch"], 2);
        assert!(requests[4].1.get("requestedAppEpoch").is_none());
        let mut expected = serde_json::to_value(info).unwrap();
        expected["operation"] = "app_get_key".into();
        assert_eq!(requests[0].1, expected);
        assert_eq!(requests[2].1["requestedAppEpoch"], 0);
        assert!(requests[0].1.get("requestedRootEpoch").is_none());
        assert_eq!(requests[2].1["requestedRootEpoch"], 0);
    }

    #[test]
    fn authorization_requires_the_latest_root_epoch_fields() {
        let base = serde_json::json!({
            "authorized": true, "rejectionReason": "", "gatewayAppId": "",
            "currentRootEpoch": 0, "currentAppEpoch": 0,
            "currentRootEpochHash": format!("0x{}", "11".repeat(32)),
        });
        assert!(serde_json::from_value::<AuthorizationResult>(base.clone()).is_err());
        let mut unregistered = base.clone();
        unregistered["latestRootEpoch"] = 0.into();
        unregistered["latestRootEpochHash"] = format!("0x{}", "00".repeat(32)).into();
        let result: AuthorizationResult = serde_json::from_value(unregistered).unwrap();
        assert_eq!(result.latest_root().unwrap(), None);
        let mut invalid = base;
        invalid["latestRootEpoch"] = 0.into();
        invalid["latestRootEpochHash"] = "0x11".into();
        let result: AuthorizationResult = serde_json::from_value(invalid).unwrap();
        assert!(result.latest_root().is_err());
    }

    #[rocket::async_test]
    async fn authorization_without_epoch_fields_is_not_accepted_as_legacy() {
        let (url, server) = serve(vec![
            r#"{"isAllowed":true,"reason":"","gatewayAppId":"gw"}"#,
        ]);
        assert!(webhook(url)
            .authorize_app(&boot_info(50), Operation::AppGetKey, None, None, "")
            .await
            .is_err());
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[rocket::async_test]
    async fn root_epochs_are_read_from_info_and_sent_in_boot_checks() {
        let hash = "0x".to_string() + &"11".repeat(32);
        let (url, server) = serve(vec![
            format!(
                r#"{{"status":"ok","kmsContractAddr":"0x00","gatewayAppId":"gw","chainId":1,
                "appImplementation":"0x00","rootEpoch":3,"rootEpochHash":"{hash}"}}"#
            ),
            r#"{"status":"ok","kmsContractAddr":"0x00","gatewayAppId":"gw","chainId":1,
                "appImplementation":"0x00","rootEpoch":3}"#
                .into(),
            r#"{"isAllowed":true,"gatewayAppId":"gw","reason":""}"#.into(),
            r#"{"isAllowed":true,"gatewayAppId":"gw","reason":""}"#.into(),
        ]);
        let auth = webhook(url);
        let current = CurrentRootEpoch {
            epoch: 3,
            chain_hash: [0x11; 32],
        };

        assert_eq!(
            auth.get_info().await.unwrap().root_epochs,
            RootEpochRegistry::Current(current)
        );
        assert!(auth.get_info().await.is_err());
        let info = boot_info(50);
        auth.is_app_allowed(&info, false, Some(current))
            .await
            .unwrap();
        auth.is_app_allowed(&info, true, None).await.unwrap();

        let requests = server.join().unwrap();
        assert_eq!(requests[2].1["rootEpoch"], 3);
        assert_eq!(requests[2].1["rootEpochHash"], hash);
        assert_eq!(requests[2].1["appId"], requests[3].1["appId"]);
        assert!(requests[3].1.get("rootEpoch").is_none());
    }

    #[rocket::async_test]
    async fn malformed_backend_response_fails_closed_and_next_request_recovers() {
        let (url, server) = serve(vec![
            "not-json",
            r#"{"isAllowed":true,"gatewayAppId":"gateway","reason":"recovered"}"#,
        ]);
        let auth = webhook(url);
        let info = boot_info(30);

        let error = auth.is_app_allowed(&info, false, None).await.unwrap_err();
        assert!(error.to_string().contains("failed to decode response"));
        let recovered = auth.is_app_allowed(&info, false, None).await.unwrap();
        assert!(recovered.is_allowed);
        assert_eq!(recovered.reason, "recovered");
        assert_eq!(server.join().unwrap().len(), 2);
    }

    /// The auth backend's body is quoted into the error that reports a bad
    /// response. Byte-slicing it at a fixed offset aborts the KMS when that
    /// offset lands inside a multi-byte character, and this runs on every
    /// response, including a successful one.
    #[rocket::async_test]
    async fn a_response_with_a_multibyte_character_on_the_quoting_bound_does_not_abort() {
        let mut body = "A".repeat(MAX_QUOTED_BODY_BYTES - 1);
        body.push('\u{e9}'); // occupies bytes 511..513, so 512 is mid-character
        let (url, server) = serve(vec![body]);

        let error = webhook(url)
            .is_app_allowed(&boot_info(40), false, None)
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("failed to decode response"));
        server.join().unwrap();
    }

    #[test]
    fn a_quoted_body_is_bounded_in_bytes_and_never_splits_a_character() {
        assert_eq!(quoted_body("short"), "short");
        assert_eq!(quoted_body(&"A".repeat(600)).len(), MAX_QUOTED_BODY_BYTES);
        // Every alignment of a 2-, 3- and 4-byte character across the bound.
        for pad in MAX_QUOTED_BODY_BYTES - 4..MAX_QUOTED_BODY_BYTES {
            for wide in ['\u{e9}', '\u{4e2d}', '\u{1f600}'] {
                let body = format!("{}{wide}{}", "A".repeat(pad), "B".repeat(16));
                let quoted = quoted_body(&body);
                assert!(quoted.len() <= MAX_QUOTED_BODY_BYTES);
                assert!(body.starts_with(quoted));
            }
        }
    }
}
