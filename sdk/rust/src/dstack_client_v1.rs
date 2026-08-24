// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Client for the `dstack.guest.v1` guest-agent surface.
//!
//! A transport mirror of the six methods the agent serves at `/v1`, and nothing
//! more. There is no `sign` and no `verify` here because v1 has neither: any
//! caller that can reach this socket can ask [`DstackClientV1::get_key`] for the
//! private key and do both itself, so an RPC for it would add a round trip and
//! an entry point without adding a capability.
//!
//! Verifying a signature chain is likewise not this SDK's job. It needs no
//! client and no connection; `docs/guest-api-v1.md` specifies the rules
//! normatively, down to the trust anchor.

use anyhow::{Context, Result};
use hex::encode as hex_encode;
use http_client_unix_domain_socket::{ClientUnix, Method};
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

pub use dstack_sdk_types::dstack_v1::*;

use crate::dstack_client::{get_endpoint, BaseClient, ClientKind};

/// Client for the v1 guest-agent surface. **This is the default client**, and
/// what the unsuffixed [`crate::DstackClient`] names.
///
/// **v1 keys are not v0 keys.** Deriving under the same name here as on
/// [`crate::dstack_client::DstackClientV0`] returns different key material, by
/// design: the v0 KDF ignored the algorithm, so one secret served both curves.
/// There is no compatibility mode. An application holding assets under a v0 key
/// migrates them deliberately -- see `docs/guest-api-v1.md`.
pub struct DstackClientV1 {
    base_url: String,
    endpoint: String,
    client: ClientKind,
}

impl BaseClient for DstackClientV1 {}

impl DstackClientV1 {
    pub fn new(endpoint: Option<&str>) -> Self {
        let endpoint = get_endpoint(endpoint);
        let (base_url, client) = match endpoint {
            ref e if e.starts_with("http://") || e.starts_with("https://") => {
                (e.to_string(), ClientKind::Http)
            }
            _ => ("http://localhost".to_string(), ClientKind::Unix),
        };

        DstackClientV1 {
            base_url,
            endpoint,
            client,
        }
    }

    /// Send to `/v1/<method>`.
    ///
    /// The version prefix lives here rather than at each call site so no method
    /// can be added against the wrong surface by copying a neighbour.
    async fn send_rpc_request<S: Serialize, D: DeserializeOwned>(
        &self,
        method: &str,
        payload: &S,
    ) -> Result<D> {
        let path = format!("/v1/{method}");
        match &self.client {
            ClientKind::Http => {
                let client = Client::new();
                let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
                let res = client
                    .post(&url)
                    .json(payload)
                    .header("Content-Type", "application/json")
                    .send()
                    .await?
                    .error_for_status()?;
                Ok(res.json().await?)
            }
            ClientKind::Unix => {
                let mut unix_client = ClientUnix::try_new(&self.endpoint).await?;
                let res = unix_client
                    .send_request_json::<_, _, Value>(
                        &path,
                        Method::POST,
                        &[("Content-Type", "application/json"), ("Host", "dstack")],
                        Some(&payload),
                    )
                    .await?;
                Ok(res.1)
            }
        }
    }

    /// Issue a certificate for this application.
    ///
    /// The agent builds a CSR, signs it with the certificate's own key, and
    /// relays it to the KMS. The private key comes back with the chain and is
    /// freshly generated per call -- it is not derived from the app identity,
    /// and two identical requests produce two unrelated keys. [`Self::get_key`]
    /// is the method that derives a stable, attestable key.
    pub async fn issue_cert(&self, config: IssueCertConfig) -> Result<IssueCertResponse> {
        let response = self.send_rpc_request("IssueCert", &config).await?;
        Ok(serde_json::from_value::<IssueCertResponse>(response)?)
    }

    /// Derive an application key from `(domain, algorithm)`.
    ///
    /// `domain` is a caller-chosen domain-separation string, not a DNS name and
    /// not a path: derivation is flat, so `a/b` is unrelated to `a` and no key
    /// derives another.
    ///
    /// `algorithm` is required and must be `secp256k1` or `ed25519`. v1 has no
    /// default and no `k256` alias -- a typo is an error rather than a key of
    /// the wrong type under a name the caller misread.
    pub async fn get_key(&self, domain: &str, algorithm: &str) -> Result<GetKeyResponse> {
        if algorithm.is_empty() {
            anyhow::bail!("algorithm is required, use `secp256k1` or `ed25519`")
        }
        let data = json!({ "domain": domain, "algorithm": algorithm });
        let response = self.send_rpc_request("GetKey", &data).await?;
        Ok(serde_json::from_value::<GetKeyResponse>(response)?)
    }

    /// Produce a versioned attestation over `report_data`.
    ///
    /// v1's only CVM attestation entry point: the attestation already carries
    /// the TDX quote and event log, and unlike v0's `GetQuote` it answers on
    /// every supported platform.
    pub async fn attest(
        &self,
        report_data: Vec<u8>,
        include_boottime_gpu_evidence: bool,
    ) -> Result<AttestResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            anyhow::bail!("report data must be 1 to 64 bytes")
        }
        let config = AttestConfig::builder()
            .report_data(hex_encode(&report_data))
            .include_boottime_gpu_evidence(include_boottime_gpu_evidence)
            .build();
        let response = self.send_rpc_request("Attest", &config).await?;
        Ok(serde_json::from_value::<AttestResponse>(response)?)
    }

    /// Collect GPU evidence now, against a caller-chosen 32-byte nonce.
    ///
    /// Returns vendor-native evidence rather than a verdict: select a verifier
    /// by vendor and format, then check the signature, certificate chain,
    /// measurements and the nonce embedded in the evidence.
    pub async fn attest_gpu(&self, nonce: Vec<u8>) -> Result<AttestGpuResponse> {
        // SPDM fixes the evidence nonce at 32 bytes and the agent passes it
        // through verbatim, so a shorter one is a caller bug worth catching
        // before the round trip.
        if nonce.len() != 32 {
            anyhow::bail!("nonce must be exactly 32 bytes")
        }
        let data = json!({ "nonce": hex_encode(nonce) });
        let response = self.send_rpc_request("AttestGpu", &data).await?;
        Ok(serde_json::from_value::<AttestGpuResponse>(response)?)
    }

    /// Return this application's identity and configuration.
    ///
    /// Identity and configuration only. Nothing here is attestation, and
    /// nothing here should be trusted on its own -- it arrives over a local
    /// socket with no quote behind it. Use [`Self::attest`] for evidence.
    pub async fn info(&self) -> Result<InfoResponse> {
        let response = self.send_rpc_request("Info", &json!({})).await?;
        Ok(serde_json::from_value::<InfoResponse>(response)?)
    }

    /// Return the guest agent version.
    ///
    /// Also the cheapest probe for whether an agent serves v1 at all: it takes
    /// no arguments and touches nothing.
    pub async fn version(&self) -> Result<VersionResponse> {
        let response = self.send_rpc_request("Version", &json!({})).await?;
        serde_json::from_value::<VersionResponse>(response).context("failed to decode the response")
    }
}

/// The recommended client.
///
/// Names the v1 surface. This alias flipped in 0.6.0: it used to mean the v0
/// client, and code that was calling v0 methods through it stops compiling
/// rather than silently deriving different key material -- the v1 signatures
/// differ, and `get_key` requires an explicit `algorithm`. To stay on the
/// frozen surface, name [`crate::dstack_client::DstackClientV0`] explicitly.
pub type DstackClient = DstackClientV1;
