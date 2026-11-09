// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::utils::{deserialize_json_file, sha256, SysConfig};
use anyhow::{anyhow, bail, Context, Result};
use dcap_qvl::collateral::{CollateralClient, PHALA_PCCS_URL};
use dstack_types::{
    shared_filenames::{HOST_SHARED_DIR, SYS_CONFIG},
    Platform,
};
use host_api::{
    client::{new_client, DefaultClient, StatusError},
    Notification,
};
use ra_tls::attestation::validate_tcb;
use sodiumbox::{generate_keypair, open_sealed_box, PUBLICKEYBYTES};
use tracing::warn;

const HOST_API_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const PCCS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) struct KeyProvision {
    pub sk: [u8; 32],
    pub mr: [u8; 32],
}

pub(crate) struct HostApi {
    client: Option<DefaultClient>,
    pccs_url: Option<String>,
}

impl Default for HostApi {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl HostApi {
    pub fn new(base_url: Option<String>, pccs_url: Option<String>) -> Self {
        Self {
            client: base_url.map(new_client),
            pccs_url,
        }
    }

    pub fn load_or_default(url: Option<String>) -> Result<Self> {
        let api = match url {
            Some(url) => Self::new(Some(url), None),
            None => {
                let local_config: SysConfig =
                    deserialize_json_file(format!("{HOST_SHARED_DIR}/{SYS_CONFIG}"))?;
                let pccs = local_config.collateral_urls().pccs;
                Self::new(local_config.host_api_url, pccs)
            }
        };
        Ok(api)
    }

    pub async fn notify(&self, event: &str, payload: &str) -> Result<()> {
        match Platform::detect_or_dstack() {
            Platform::Dstack => {}
            Platform::Gcp | Platform::NitroEnclave | Platform::AwsEc2 => {
                // Skip notify on unsupported platforms
                return Ok(());
            }
        }
        let Some(client) = &self.client else {
            return Ok(());
        };
        tokio::time::timeout(
            HOST_API_TIMEOUT,
            client.notify(Notification {
                event: event.to_string(),
                payload: payload.to_string(),
            }),
        )
        .await
        .context("Timed out notifying Host API")??;
        Ok(())
    }

    /// Close the host's env update window for this boot, handing it the env
    /// re-encrypted to the current root epoch, or an empty one when nothing
    /// changed. An error means the window may still be open.
    pub async fn update_sealed_env(&self, sealed_env: Vec<u8>) -> Result<()> {
        if !matches!(Platform::detect_or_dstack(), Platform::Dstack) {
            return Ok(());
        }
        let Some(client) = &self.client else {
            return Ok(());
        };
        let response = tokio::time::timeout(
            HOST_API_TIMEOUT,
            client.update_sealed_env(host_api::SealedEnv { sealed_env }),
        )
        .await
        .context("Timed out updating the sealed env on the host")?;
        match response {
            // A VMM predating UpdateSealedEnv has no window to close.
            Err(err) if is_unknown_method(&err) => Ok(()),
            response => response.map(drop),
        }
    }

    pub async fn notify_q(&self, event: &str, payload: &str) {
        if let Err(err) = self.notify(event, payload).await {
            warn!("Failed to notify event {event} to host: {:?}", err);
        }
    }

    pub async fn get_sealing_key(&self) -> Result<KeyProvision> {
        let (pk, sk) = generate_keypair();
        let mut report_data = [0u8; 64];
        report_data[..PUBLICKEYBYTES].copy_from_slice(pk.as_bytes());
        let quote = tdx_attest::get_quote(&report_data).context("Failed to get quote")?;
        let Some(client) = &self.client else {
            return Err(anyhow!("Host API client not initialized"));
        };
        let provision = tokio::time::timeout(
            HOST_API_TIMEOUT,
            client.get_sealing_key(host_api::GetSealingKeyRequest {
                quote: quote.to_vec(),
            }),
        )
        .await
        .context("Timed out requesting sealing key from Host API")?
        .map_err(|err| anyhow!("Failed to get sealing key: {err:?}"))?;

        // verify the key provider quote
        let pccs_url = self
            .pccs_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .unwrap_or(PHALA_PCCS_URL);
        let collateral_client = CollateralClient::with_default_http(pccs_url)?;
        let verified_report = tokio::time::timeout(
            PCCS_TIMEOUT,
            collateral_client.fetch_and_verify(&provision.provider_quote),
        )
        .await
        .context("Timed out fetching sealing-key quote collateral")?
        .context("Failed to get quote collateral")?;
        validate_tcb(&verified_report)?;
        let sgx_report = verified_report
            .report
            .as_sgx()
            .context("Invalid sgx report")?;
        let key_hash = sha256(&provision.encrypted_key);
        if sgx_report.report_data[..32] != key_hash {
            bail!("Invalid key hash");
        }
        let mr = sgx_report.mr_enclave;

        // write to fs
        let sealing_key = open_sealed_box(&provision.encrypted_key, &pk, &sk)
            .ok()
            .context("Failed to open sealing key")?;
        let sk = sealing_key
            .try_into()
            .ok()
            .context("Invalid sealing key length")?;
        Ok(KeyProvision { sk, mr })
    }
}

/// Whether the host does not implement the method at all: a VMM since 0.6
/// answers 404, and older ones 400 with the pRPC dispatcher's fixed
/// "Service not found" message.
fn is_unknown_method(err: &anyhow::Error) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<StatusError>())
        .is_some_and(|err| {
            err.status == 404
                || (err.status == 400
                    && err
                        .message
                        .as_deref()
                        .is_some_and(|message| message.starts_with("Service not found: ")))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A host API answering one request with `status` and a JSON `body`.
    fn host(status: u16, body: String) -> HostApi {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..read]);
            }
            write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        HostApi::new(Some(url), None)
    }

    #[tokio::test]
    async fn only_an_answer_or_a_host_without_a_window_closes_the_env_window() {
        assert!(matches!(Platform::detect_or_dstack(), Platform::Dstack));
        let unknown = r#"{"error":"Service not found: UpdateSealedEnv"}"#;
        for (status, body, closed) in [
            (200, "", true),
            // A VMM since 0.6, and one before, that does not know the method.
            (404, unknown, true),
            (400, unknown, true),
            // Anything else may leave the window open.
            (400, r#"{"error":"VM not found"}"#, false),
            (500, "{}", false),
        ] {
            let result = host(status, body.into())
                .update_sealed_env(b"env".to_vec())
                .await;
            assert_eq!(result.is_ok(), closed, "{status} {body}");
        }
        // No host listening at all.
        let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", gone.local_addr().unwrap());
        drop(gone);
        assert!(HostApi::new(Some(url), None)
            .update_sealed_env(Vec::new())
            .await
            .is_err());
        // No host API configured means no window.
        HostApi::new(None, None)
            .update_sealed_env(Vec::new())
            .await
            .unwrap();
    }
}
