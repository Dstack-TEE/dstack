// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{kms_client::KmsClient, SignCertRequest};
use dstack_types::{AppKeys, KeyProvider};
use ra_rpc::client::{CertInfo, RaClient, RaClientConfig};
use ra_tls::cert::{generate_ra_cert, CaCert, CertSigningRequestV2};

/// The usage the KMS stamps on its own RPC certificate.
///
/// Every other certificate it signs belongs to an app and carries `app:custom`.
const KMS_RPC_CERT_USAGE: &str = "kms:rpc";

/// Refuse a KMS connection whose server certificate is not the KMS's own.
///
/// The pinned CA is the KMS root, and the KMS also signs app certificates
/// under that root with whatever subject alternative names the app's CSR asks
/// for. Pinning the root alone therefore authenticates "some app this KMS
/// authorized", not "this KMS". The KMS writes `kms:rpc` only on its own RPC
/// certificate, which is what dstack-util already checks before fetching app
/// keys.
fn validate_kms_rpc_cert(cert: Option<CertInfo>) -> Result<()> {
    let Some(cert) = cert else {
        bail!("missing server cert");
    };
    let Some(usage) = cert.special_usage else {
        bail!("missing server cert usage");
    };
    if usage != KMS_RPC_CERT_USAGE {
        bail!("invalid server cert usage: {usage}");
    }
    Ok(())
}

pub enum CertRequestClient {
    Local {
        ca: Box<CaCert>,
    },
    Kms {
        client: KmsClient<RaClient>,
        vm_config: String,
    },
}

impl CertRequestClient {
    pub async fn sign_csr(
        &self,
        csr: &CertSigningRequestV2,
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
                        api_version: 2,
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
            KeyProvider::None { key }
            | KeyProvider::Local { key, .. }
            | KeyProvider::Tpm { key, .. } => {
                let ca = CaCert::new(keys.ca_cert.clone(), key.clone())
                    .context("Failed to create CA")?;
                Ok(CertRequestClient::Local { ca: Box::new(ca) })
            }
            KeyProvider::Kms {
                url,
                tmp_ca_key,
                tmp_ca_cert,
                ..
            } => {
                let client_cert = generate_ra_cert(tmp_ca_cert.clone(), tmp_ca_key.clone())
                    .context("Failed to generate RA cert")?;
                let ra_client = RaClientConfig::builder()
                    .remote_uri(url.clone())
                    .tls_client_cert(client_cert.cert_pem)
                    .tls_client_key(client_cert.key_pem)
                    .tls_ca_cert(keys.ca_cert.clone())
                    .tls_built_in_root_certs(false)
                    .maybe_pccs_url(pccs_url.map(|s| s.to_string()))
                    // Root pin plus `kms:rpc` already identify the KMS; re-verifying
                    // its quote on every request would only add a collateral fetch.
                    .verify_server_attestation(false)
                    .cert_validator(Box::new(validate_kms_rpc_cert))
                    .build()
                    .into_client()
                    .context("Failed to create RA client")?;
                let client = KmsClient::new(ra_client);
                Ok(CertRequestClient::Kms { client, vm_config })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(usage: Option<&str>) -> Option<CertInfo> {
        Some(CertInfo {
            cert_der: vec![],
            attestation: None,
            special_usage: usage.map(str::to_string),
            app_id: None,
        })
    }

    #[test]
    fn only_the_kms_rpc_cert_is_accepted() {
        validate_kms_rpc_cert(cert(Some("kms:rpc"))).unwrap();
        assert!(validate_kms_rpc_cert(cert(Some("app:custom"))).is_err());
        assert!(validate_kms_rpc_cert(cert(None)).is_err());
        assert!(validate_kms_rpc_cert(None).is_err());
    }
}
