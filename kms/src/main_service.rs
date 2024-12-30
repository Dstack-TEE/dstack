use std::sync::Arc;

use anyhow::{bail, Context, Result};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyResponse, GetAppKeyRequest, GetMetaResponse, PublicKeyResponse,
};
use ra_rpc::{CallContext, RpcCall};
use ra_tls::{
    attestation::Attestation,
    cert::{CaCert, CertRequest},
    kdf,
};
use upgrade_authority::BootInfo;

use crate::{config::KmsConfig, crypto::derive_k256_key};

mod upgrade_authority;

#[derive(Clone)]
pub struct KmsState {
    inner: Arc<KmsStateInner>,
}

impl std::ops::Deref for KmsState {
    type Target = KmsStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct KmsStateInner {
    config: KmsConfig,
    root_ca: CaCert,
    ecdsa_root_key: SigningKey,
}

impl KmsState {
    pub fn new(config: KmsConfig) -> Result<Self> {
        let root_ca = CaCert::load(&config.root_ca_cert, &config.root_ca_key)
            .context("Failed to load root CA certificate")?;
        let key_bytes =
            fs::read(&config.ecdsa_root_key).context("Failed to read ECDSA root key")?;
        let ecdsa_root_key =
            SigningKey::from_slice(&key_bytes).context("Failed to load ECDSA root key")?;
        Ok(Self {
            inner: Arc::new(KmsStateInner {
                config,
                root_ca,
                ecdsa_root_key,
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

        let app_key = kdf::derive_ecdsa_key_pair(
            &self.state.root_ca.key,
            &[&app_id[..], "app-key".as_bytes()],
        )
        .context("Failed to derive app key")?;

        let context_data = vec![&app_id[..], &instance_id[..], b"app-disk-crypt-key"];
        let app_disk_key = kdf::derive_dh_secret(&self.state.root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        let todo = "TODO: Add ecdsa key";
        let env_crypt_key = {
            let secret =
                kdf::derive_dh_secret(&self.state.root_ca.key, &[&app_id[..], b"env-encrypt-key"])
                    .context("Failed to derive env encrypt key")?;
            let secret = x25519_dalek::StaticSecret::from(secret);
            secret.to_bytes()
        };
        let app_id_str = hex::encode(&app_id);
        let subject = format!("{app_id_str}{}", self.state.config.subject_postfix);
        let req = CertRequest::builder()
            .subject(&subject)
            .ca_level(1)
            .quote(&attest.quote)
            .event_log(&attest.raw_event_log)
            .key(&app_key)
            .build();

        let cert = self
            .state
            .root_ca
            .sign(req)
            .context("Failed to sign certificate")?
            .pem();

        let (app_ecdsa_key, app_ecdsa_signature) = {
            let (app_ecdsa_key, signature, recid) = derive_k256_key(
                &self.state.ecdsa_root_key,
                &[&app_id[..], "app-key".as_bytes()],
            )
            .context("Failed to derive app ecdsa key")?;

            let mut signature = signature.to_vec();
            signature.push(recid.to_byte());
            (app_ecdsa_key.to_bytes().to_vec(), signature)
        };

        Ok(AppKeyResponse {
            disk_crypt_key: app_disk_key.to_vec(),
            env_crypt_key: env_crypt_key.to_vec(),
            app_key: app_key.serialize_pem(),
            certificate_chain: vec![cert, self.state.root_ca.cert.pem()],
            app_ecdsa_key,
            app_ecdsa_signature,
        })
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        let secret = kdf::derive_dh_secret(
            &self.state.root_ca.key,
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
