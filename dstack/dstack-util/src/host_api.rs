// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::utils::{deserialize_json_file, sha256, SysConfig};
use anyhow::{anyhow, bail, Context, Result};
use dstack_types::{
    shared_filenames::{HOST_SHARED_DIR, SYS_CONFIG},
    Platform,
};
use host_api::{
    client::{new_client, DefaultClient},
    Notification,
};
use ra_tls::attestation::validate_tcb;
use sodiumbox::{generate_keypair, open_sealed_box, PUBLICKEYBYTES};
use tracing::warn;

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
                Self::new(local_config.host_api_url, local_config.pccs_url)
            }
        };
        Ok(api)
    }

    pub async fn notify(&self, event: &str, payload: &str) -> Result<()> {
        match Platform::detect_or_dstack() {
            Platform::Dstack => {}
            Platform::Gcp | Platform::NitroEnclave => {
                // Skip notify on unsupported platforms
                return Ok(());
            }
        }
        let Some(client) = &self.client else {
            return Ok(());
        };
        client
            .notify(Notification {
                event: event.to_string(),
                payload: payload.to_string(),
            })
            .await?;
        Ok(())
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
        let provision = client
            .get_sealing_key(host_api::GetSealingKeyRequest {
                quote: quote.to_vec(),
            })
            .await
            .map_err(|err| anyhow!("Failed to get sealing key: {err:?}"))?;

        // verify the key provider quote
        let verified_report = dcap_qvl::collateral::get_collateral_and_verify(
            &provision.provider_quote,
            self.pccs_url.as_deref(),
        )
        .await
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
