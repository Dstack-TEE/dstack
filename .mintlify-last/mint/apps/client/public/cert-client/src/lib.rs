use anyhow::{Context, Result};
use dstack_kms_rpc::{kms_client::KmsClient, SignCertRequest};
use dstack_types::{AppKeys, KeyProvider};
use ra_rpc::client::{RaClient, RaClientConfig};
use ra_tls::{
    attestation::QuoteContentType,
    cert::{generate_ra_cert, CaCert, CertConfig, CertSigningRequest},
    rcgen::KeyPair,
};
use tdx_attest::{eventlog::read_event_logs, get_quote};

pub enum CertRequestClient {
    Local {
        ca: CaCert,
    },
    Kms {
        client: KmsClient<RaClient>,
        vm_config: String,
    },
}

impl CertRequestClient {
    pub async fn sign_csr(
        &self,
        csr: &CertSigningRequest,
        signature: &[u8],
    ) -> Result<Vec<String>> {
        match self {
            CertRequestClient::Local { ca } => {
                let cert = ca
                    .sign_csr(csr, None, "app:custom")
                    .context("Failed to sign certificate")?;
                Ok(vec![cert.pem(), ca.pem_cert.clone()])
            }
            CertRequestClient::Kms { client, vm_config } => {
                let response = client
                    .sign_cert(SignCertRequest {
                        api_version: 1,
                        csr: csr.to_vec(),
                        signature: signature.to_vec(),
                        vm_config: vm_config.clone(),
                    })
                    .await?;
                Ok(response.certificate_chain)
            }
        }
    }

    pub async fn get_root_ca(&self) -> Result<String> {
        match self {
            CertRequestClient::Local { ca } => Ok(ca.pem_cert.clone()),
            CertRequestClient::Kms { client, .. } => Ok(client.get_meta().await?.ca_cert),
        }
    }

    pub async fn create(
        keys: &AppKeys,
        pccs_url: Option<&str>,
        vm_config: String,
    ) -> Result<CertRequestClient> {
        match &keys.key_provider {
            KeyProvider::Local { key } => {
                let ca = CaCert::new(keys.ca_cert.clone(), key.clone())
                    .context("Failed to create CA")?;
                Ok(CertRequestClient::Local { ca })
            }
            KeyProvider::Kms { url } => {
                let tmp_client =
                    RaClient::new(url.into(), true).context("Failed to create RA client")?;
                let tmp_client = KmsClient::new(tmp_client);
                let tmp_ca = tmp_client
                    .get_temp_ca_cert()
                    .await
                    .context("Failed to get temp CA cert")?;
                let client_cert = generate_ra_cert(tmp_ca.temp_ca_cert, tmp_ca.temp_ca_key)
                    .context("Failed to generate RA cert")?;
                let ra_client = RaClientConfig::builder()
                    .remote_uri(url.clone())
                    .tls_client_cert(client_cert.cert_pem)
                    .tls_client_key(client_cert.key_pem)
                    .tls_ca_cert(keys.ca_cert.clone())
                    .tls_built_in_root_certs(false)
                    .maybe_pccs_url(pccs_url.map(|s| s.to_string()))
                    .build()
                    .into_client()
                    .context("Failed to create RA client")?;
                let client = KmsClient::new(ra_client);
                Ok(CertRequestClient::Kms { client, vm_config })
            }
        }
    }

    pub async fn request_cert(
        &self,
        key: &KeyPair,
        config: CertConfig,
        no_ra: bool,
    ) -> Result<Vec<String>> {
        let pubkey = key.public_key_der();
        let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
        let (quote, event_log) = if !no_ra {
            let (_, quote) = get_quote(&report_data, None).context("Failed to get quote")?;
            let event_log = read_event_logs().context("Failed to decode event log")?;
            let event_log =
                serde_json::to_vec(&event_log).context("Failed to serialize event log")?;
            (quote, event_log)
        } else {
            (vec![], vec![])
        };

        let csr = CertSigningRequest {
            confirm: "please sign cert:".to_string(),
            pubkey,
            config,
            quote,
            event_log,
        };
        let signature = csr.signed_by(key).context("Failed to sign the CSR")?;
        self.sign_csr(&csr, &signature)
            .await
            .context("Failed to sign the CSR")
    }
}
