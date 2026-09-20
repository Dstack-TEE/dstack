// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use prpc::{
    client::{Error, RequestClient},
    Message,
};
use ra_tls::{
    attestation::{AttestationVerifier, VerifiedAttestation},
    traits::CertExt,
};
use reqwest::{tls::TlsInfo, Certificate, Client, Identity, Response};
use serde::{de::DeserializeOwned, Serialize};

use bon::Builder;

pub struct CertInfo {
    pub cert_der: Vec<u8>,
    pub attestation: Option<VerifiedAttestation>,
    pub special_usage: Option<String>,
    pub app_id: Option<Vec<u8>>,
}

type CertValidator = Box<dyn Fn(Option<CertInfo>) -> Result<()> + Send + Sync + 'static>;

#[derive(Builder)]
pub struct RaClientConfig {
    remote_uri: String,
    #[builder(default = false)]
    tls_no_check: bool,
    #[builder(default = true)]
    verify_server_attestation: bool,
    #[builder(default = false)]
    tls_no_check_hostname: bool,
    tls_client_cert: Option<String>,
    tls_client_key: Option<String>,
    tls_ca_cert: Option<String>,
    #[builder(default = true)]
    tls_built_in_root_certs: bool,
    attestation_verifier: Option<Arc<AttestationVerifier>>,
    cert_validator: Option<CertValidator>,
}

impl RaClientConfig {
    pub fn into_client(self) -> Result<RaClient> {
        let mut builder = Client::builder()
            .tls_sni(true)
            .danger_accept_invalid_certs(self.tls_no_check)
            .danger_accept_invalid_hostnames(self.tls_no_check_hostname)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60));
        if self.cert_validator.is_some() {
            builder = builder.tls_info(true);
        }
        if let (Some(cert_pem), Some(key_pem)) = (self.tls_client_cert, self.tls_client_key) {
            let identity_pem = format!("{cert_pem}\n{key_pem}");
            let identity =
                Identity::from_pem(identity_pem.as_bytes()).context("Failed to parse identity")?;
            builder = builder.identity(identity);
        }
        // reqwest 0.13 replaced tls_built_in_root_certs / add_root_certificate with
        // tls_certs_merge (keep platform roots) and tls_certs_only (custom roots only).
        // Hostname-check bypass also requires tls_certs_only on the rustls backend.
        let ca_cert = self
            .tls_ca_cert
            .as_deref()
            .map(|ca| Certificate::from_pem(ca.as_bytes()).context("Failed to parse CA"))
            .transpose()?;
        if self.tls_built_in_root_certs && !self.tls_no_check_hostname {
            if let Some(ca) = ca_cert {
                builder = builder.tls_certs_merge([ca]);
            }
        } else {
            builder = builder.tls_certs_only(ca_cert);
        }
        let client = builder.build().context("failed to create client")?;
        let attestation_verifier = self
            .attestation_verifier
            .map(Ok)
            .unwrap_or_else(|| AttestationVerifier::new_prod(None).map(Arc::new))?;
        Ok(RaClient {
            remote_uri: self.remote_uri,
            attestation_verifier,
            client,
            cert_validator: self.cert_validator,
            verify_server_attestation: self.verify_server_attestation,
        })
    }
}

pub struct RaClient {
    remote_uri: String,
    attestation_verifier: Arc<AttestationVerifier>,
    client: Client,
    cert_validator: Option<CertValidator>,
    verify_server_attestation: bool,
}

impl RaClient {
    pub fn new(remote_uri: String, tls_no_check: bool) -> Result<Self> {
        RaClientConfig::builder()
            .tls_no_check(tls_no_check)
            .remote_uri(remote_uri)
            .build()
            .into_client()
            .context("failed to create client")
    }

    async fn try_validate_attestation(&self, response: &Response) -> Result<()> {
        let Some(validator) = &self.cert_validator else {
            return Ok(());
        };

        let Some(tls_info) = response.extensions().get::<TlsInfo>() else {
            bail!("No TLS info in response");
        };
        let Some(cert) = tls_info.peer_certificate() else {
            return validator(None);
        };
        let cert_der = cert.to_vec();
        let (_, cert) =
            x509_parser::parse_x509_certificate(cert).context("Failed to parse certificate")?;
        let special_usage = cert
            .get_special_usage()
            .context("Failed to get special usage")?;
        let app_id = cert.get_app_id().context("Failed to get app id")?;
        let attestation = if !self.verify_server_attestation {
            None
        } else {
            match ra_tls::attestation::from_cert(&cert).context("Failed to parse attestation")? {
                None => None,
                Some(attestation) => {
                    let verified_attestation = attestation
                        .into_v1()
                        .verify_with_ra_pubkey(cert.public_key().raw, &self.attestation_verifier)
                        .await
                        .context(
                            "failed to verify the attestation report presented by the server",
                        )?;
                    Some(verified_attestation)
                }
            }
        };
        let cert_info = CertInfo {
            cert_der,
            attestation,
            special_usage,
            app_id,
        };
        validator(Some(cert_info))
    }
}

fn normalize_json_response_body(body: &[u8]) -> &[u8] {
    if body.is_empty() {
        b"null"
    } else {
        body
    }
}

#[cfg(test)]
mod response_tests {
    use super::normalize_json_response_body;

    #[test]
    fn empty_json_response_decodes_as_unit() {
        let value: () = serde_json::from_slice(normalize_json_response_body(b""))
            .expect("empty response should decode as unit");
        assert_eq!(value, ());
    }

    #[test]
    fn non_empty_json_response_is_unchanged() {
        assert_eq!(
            normalize_json_response_body(br#"{"value":1}"#),
            br#"{"value":1}"#
        );
    }
}

impl RequestClient for RaClient {
    async fn request<T, R>(&self, path: &str, body: T) -> Result<R, Error>
    where
        T: Message + Serialize,
        R: Message + DeserializeOwned,
    {
        let body = serde_json::to_vec(&body).context("Failed to serialize body")?;
        let url = format!("{}/{}?json", self.remote_uri, path);
        let response = self
            .client
            .post(url)
            .body(body)
            .send()
            .await
            .context("Failed to send request")?;

        // Name the direction explicitly: this validates the *server's* attestation,
        // not the client's own quote. Without it the error chain reads as if the
        // remote end rejected us.
        self.try_validate_attestation(&response)
            .await
            .with_context(|| {
                format!(
                    "failed to validate the server attestation of {}",
                    self.remote_uri
                )
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("Request failed with status={status}, error={body}");
        }
        let body = response
            .bytes()
            .await
            .context("Failed to read response")?
            .to_vec();
        let response = serde_json::from_slice(normalize_json_response_body(&body))
            .context("Failed to deserialize response")?;
        Ok(response)
    }
}
