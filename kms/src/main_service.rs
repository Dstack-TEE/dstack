use std::sync::Arc;

use anyhow::{bail, Context, Result};
use kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyResponse, PublicKeyResponse,
};
use ra_rpc::RpcCall;
use ra_tls::{
    attestation::Attestation,
    cert::{CaCert, CertRequest},
    kdf::{derive_dh_secret, derive_ecdsa_key_pair},
    qvl::quote::{Report, TDReport10},
};
use tracing::warn;

use crate::{
    config::{AllowedMr, KmsConfig},
    ct_log::ct_log_write_cert,
};
use fs_err as fs;

#[derive(Clone)]
pub struct KmsState {
    inner: Arc<KmsStateInner>,
}

struct KmsStateInner {
    config: KmsConfig,
    root_ca: CaCert,
}

impl KmsState {
    fn lock(&self) -> &KmsStateInner {
        &self.inner
    }

    pub fn new(config: KmsConfig) -> Result<Self> {
        let ca_cert = CaCert::load(&config.root_ca_cert, &config.root_ca_key)
            .context("Failed to load root CA certificate")?;
        Ok(Self {
            inner: Arc::new(KmsStateInner {
                config,
                root_ca: ca_cert,
            }),
        })
    }
}

pub struct RpcHandler {
    state: KmsState,
    attestation: Option<Attestation>,
}

impl AllowedMr {
    pub fn is_allowed(&self, report: &TDReport10) -> bool {
        if self.allow_all {
            return true;
        }
        self.mrtd.contains(&report.mr_td)
            && self.rtmr0.contains(&report.rt_mr0)
            && self.rtmr1.contains(&report.rt_mr1)
            && self.rtmr2.contains(&report.rt_mr2)
    }
}

impl RpcHandler {
    fn ensure_attested(&self) -> Result<&Attestation> {
        let Some(attestation) = &self.attestation else {
            bail!("No attestation provided");
        };
        // if !attestation.is_verified() {
        //     bail!("The quote is not verified");
        // }
        let quote = attestation.decode_quote()?;

        let report = match quote.report {
            Report::SgxEnclave(_) => bail!("SGX enclave is not supported"),
            Report::TD10(r) => r,
            Report::TD15(r) => r.base,
        };
        if !self.state.inner.config.allowed_mr.is_allowed(&report) {
            bail!("Forbidden MR");
        }
        Ok(attestation)
    }

    fn ensure_app_allowed(&self, app_id: &str, compose_hash: &str) -> Result<()> {
        fn truncate(s: &str, len: usize) -> &str {
            if s.len() > len {
                &s[..len]
            } else {
                s
            }
        }
        let truncated_compose_hash = truncate(compose_hash, 40);
        if app_id == truncated_compose_hash {
            return Ok(());
        }
        if self.state.inner.config.allow_any_upgrade {
            return Ok(());
        }
        let registry_dir = &self.state.inner.config.upgrade_registry_dir;
        let flag_file_path = format!("{registry_dir}/{app_id}/{truncated_compose_hash}");
        if fs::metadata(&flag_file_path).is_ok() {
            return Ok(());
        }
        warn!("Denied to load {app_id} of hash {compose_hash}");
        bail!("Compose hash denied");
    }
}

impl KmsRpc for RpcHandler {
    async fn get_app_key(self) -> Result<AppKeyResponse> {
        let attest = self.ensure_attested()?;
        let app_id = attest.decode_app_id().context("Failed to decode app ID")?;
        let instance_id = attest
            .decode_instance_id()
            .context("Failed to decode instance ID")?;
        let compose_hash = attest
            .decode_compose_hash()
            .context("Failed to decode compose hash")?;
        self.ensure_app_allowed(&app_id, &compose_hash)
            .context("App not allowed")?;
        let rootfs_hash = attest
            .decode_rootfs_hash()
            .context("Failed to decode rootfs hash")?;

        let state = self.state.lock();

        let app_key = derive_ecdsa_key_pair(
            &state.root_ca.key,
            &[app_id.as_bytes(), "app-key".as_bytes()],
        )
        .context("Failed to derive app key")?;

        let app_disk_key = derive_ecdsa_key_pair(
            &state.root_ca.key,
            &[
                rootfs_hash.as_bytes(),
                app_id.as_bytes(),
                instance_id.as_bytes(),
                "app-disk-crypt-key".as_bytes(),
            ],
        )
        .context("Failed to derive app disk key")?;

        let env_crypt_key = {
            let secret = derive_dh_secret(
                &state.root_ca.key,
                &[app_id.as_bytes(), "env-encrypt-key".as_bytes()],
            )
            .context("Failed to derive env encrypt key")?;
            let secret = x25519_dalek::StaticSecret::from(secret);
            secret.to_bytes()
        };
        let subject = format!("{app_id}{}", state.config.subject_postfix);
        let req = CertRequest::builder()
            .subject(&subject)
            .ca_level(1)
            .quote(&attest.quote)
            .event_log(&attest.raw_event_log)
            .key(&app_key)
            .build();

        let cert = state
            .root_ca
            .sign(req)
            .context("Failed to sign certificate")?
            .pem();

        ct_log_write_cert(&app_id, &cert, &state.config.cert_log_dir)
            .context("failed to log certificate")?;

        Ok(AppKeyResponse {
            app_key: app_key.serialize_pem(),
            disk_crypt_key: app_disk_key.serialize_der(),
            env_crypt_key: env_crypt_key.to_vec(),
            certificate_chain: vec![cert, state.root_ca.cert.pem()],
        })
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        let secret = derive_dh_secret(
            &self.state.lock().root_ca.key,
            &[request.app_id.as_bytes(), "env-encrypt-key".as_bytes()],
        )
        .context("Failed to derive env encrypt key")?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let pubkey = x25519_dalek::PublicKey::from(&secret);
        Ok(PublicKeyResponse {
            public_key: pubkey.to_bytes().to_vec(),
        })
    }
}

impl RpcCall<KmsState> for RpcHandler {
    type PrpcService = KmsServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        KmsServer::new(self)
    }

    fn construct(state: &KmsState, attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler {
            state: state.clone(),
            attestation,
        })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <KmsServer<RpcHandler>>::supported_methods()
}
