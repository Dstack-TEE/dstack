use std::time::{Duration, SystemTime};

use crate::utils::{deserialize_json_file, sha256, LocalConfig};
use anyhow::{anyhow, bail, Context, Result};
use host_api::{
    client::{new_client, DefaultClient},
    Notification,
};
use key_provider_client::guest::{generate_keypair, open_sealed_box, PUBLICKEYBYTES};
use tracing::warn;

pub(crate) struct KeyProvision {
    pub sk: [u8; 32],
    pub mr: [u8; 32],
}

pub(crate) struct HostApi {
    client: DefaultClient,
    pccs_url: Option<String>,
}

impl Default for HostApi {
    fn default() -> Self {
        Self::new("".into(), None)
    }
}

impl HostApi {
    pub fn new(base_url: String, pccs_url: Option<String>) -> Self {
        Self {
            client: new_client(base_url),
            pccs_url,
        }
    }

    pub fn load_or_default(url: Option<String>) -> Result<Self> {
        let api = match url {
            Some(url) => Self::new(url, None),
            None => {
                let local_config: LocalConfig = deserialize_json_file("/tapp/config.json")?;
                Self::new(
                    local_config.host_api_url.clone(),
                    local_config.pccs_url.clone(),
                )
            }
        };
        Ok(api)
    }

    pub async fn notify(&self, event: &str, payload: &str) -> Result<()> {
        self.client
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
        report_data[..PUBLICKEYBYTES].copy_from_slice(&pk.0);
        let (_, quote) =
            tdx_attest::get_quote(&report_data, None).context("Failed to get quote")?;

        let provision = self
            .client
            .get_sealing_key(host_api::GetSealingKeyRequest {
                quote: quote.to_vec(),
            })
            .await
            .map_err(|err| anyhow!("Failed to get sealing key: {err:?}"))?;

        // verify the key provider quote
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("Invalid system time")?
            .as_secs();

        let pccs_url = self.pccs_url.as_deref().unwrap_or_default();
        let pccs_url = if pccs_url.is_empty() {
            "https://api.trustedservices.intel.com/sgx/certification/v4"
        } else {
            pccs_url
        };
        let quote_collateral = dcap_qvl::collateral::get_collateral(
            pccs_url,
            &provision.provider_quote,
            Duration::from_secs(10),
        )
        .await
        .context("Failed to get quote collateral")?;
        let verified_report =
            dcap_qvl::verify::verify(&provision.provider_quote, &quote_collateral, now)
                .ok()
                .context("Failed to verify key provider quote")?;
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