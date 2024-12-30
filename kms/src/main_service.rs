use std::sync::Arc;

use anyhow::{bail, Context, Result};
use kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyResponse, GetAppKeyRequest, GetMetaResponse, PublicKeyResponse,
};
use ra_rpc::{CallContext, RpcCall};
use ra_tls::{
    attestation::Attestation,
    cert::{CaCert, CertRequest},
    kdf::{derive_dh_secret, derive_ecdsa_key_pair},
};
use upgrade_authority::BootInfo;

use crate::{config::KmsConfig, ct_log::ct_log_write_cert};

mod upgrade_authority;

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

impl RpcHandler {
    fn ensure_attested(&self) -> Result<&Attestation> {
        let Some(attestation) = &self.attestation else {
            bail!("No attestation provided");
        };
        Ok(attestation)
    }

    async fn ensure_app_allowed(&self) -> Result<BootInfo> {
        let att = self.ensure_attested()?;
        let report = att.verified_report.as_ref().context("No verified report")?;
        let report = report
            .report
            .as_td10()
            .context("Failed to decode TD report")?;
        let mrtd = report.mr_td.to_vec();
        let image_hash = concat_sha256(&[&report.rt_mr0, &report.rt_mr1, &report.rt_mr2]).to_vec();
        let app_info = att.decode_app_info()?;
        let boot_info = BootInfo {
            mrtd,
            image_hash,
            rootfs_hash: app_info.rootfs_hash,
            app_id: app_info.app_id,
            compose_hash: app_info.compose_hash,
            instance_id: app_info.instance_id,
            device_id: app_info.device_id,
        };
        let response = self
            .state
            .lock()
            .config
            .boot_authority
            .is_allowed(&boot_info)
            .await?;
        if !response.is_allowed {
            bail!("Boot denied: {}", response.reason);
        }
        Ok(boot_info)
    }
}

impl KmsRpc for RpcHandler {
    async fn get_app_key(self, _request: GetAppKeyRequest) -> Result<AppKeyResponse> {
        let attest = self.ensure_attested()?;
        let boot_info = self.ensure_app_allowed().await.context("App not allowed")?;
        let app_id = boot_info.app_id;
        let instance_id = boot_info.instance_id;

        let state = self.state.lock();

        let app_key =
            derive_ecdsa_key_pair(&state.root_ca.key, &[&app_id[..], "app-key".as_bytes()])
                .context("Failed to derive app key")?;
        let context_data = vec![&app_id[..], &instance_id[..], b"app-disk-crypt-key"];
        let app_disk_key = derive_dh_secret(&state.root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        derive_ecdsa_key_pair(&state.root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;

        let todo = "TODO: Add ecdsa key";
        let env_crypt_key = {
            let secret = derive_dh_secret(&state.root_ca.key, &[&app_id[..], b"env-encrypt-key"])
                .context("Failed to derive env encrypt key")?;
            let secret = x25519_dalek::StaticSecret::from(secret);
            secret.to_bytes()
        };
        let app_id = hex::encode(&app_id);
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
            disk_crypt_key: app_disk_key.to_vec(),
            env_crypt_key: env_crypt_key.to_vec(),
            app_key: app_key.serialize_pem(),
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

    async fn get_meta(self) -> Result<GetMetaResponse> {
        Ok(GetMetaResponse {
            ca_cert: self.state.inner.root_ca.cert.pem(),
            allow_any_upgrade: self.state.inner.config.boot_authority.is_dev(),
        })
    }
}

impl RpcCall<KmsState> for RpcHandler {
    type PrpcService = KmsServer<Self>;

    fn construct(context: CallContext<'_, KmsState>) -> Result<Self> {
        Ok(RpcHandler {
            state: context.state.clone(),
            attestation: context.attestation,
        })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <KmsServer<RpcHandler>>::supported_methods()
}

fn concat_sha256(hashes: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}
