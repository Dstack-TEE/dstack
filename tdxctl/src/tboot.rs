use anyhow::{anyhow, bail, Context, Result};
use cert_client::CertRequestClient;
use clap::Parser;
use cmd_lib::run_fun as cmd;
use fs_err as fs;
use ra_rpc::client::{CertInfo, RaClientConfig};
use ra_tls::{
    cert::CertConfig,
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
use serde_json::Value;
use std::collections::BTreeMap;
use tproxy_rpc::{tproxy_client::TproxyClient, RegisterCvmRequest};
use tracing::info;

use crate::{
    host_api::HostApi,
    utils::{deserialize_json_file, AppCompose, AppKeys, LocalConfig},
};

#[derive(Parser)]
/// Boot the Tapp
pub(crate) struct TbootArgs {
    /// shutdown if the tboot fails
    #[arg(long)]
    pub(crate) shutdown_on_fail: bool,
    /// Source directory
    #[arg(short, long, default_value = "")]
    prefix: String,
}

impl TbootArgs {
    pub(crate) fn resolve(&self, path: &str) -> String {
        format!("{}/{}", self.prefix, path)
    }
}

struct RaValidator {
    remote_app_id: String,
}

impl RaValidator {
    fn validate(&self, cert: Option<CertInfo>) -> Result<()> {
        if self.remote_app_id == "any" {
            return Ok(());
        }
        let Some(cert) = cert else {
            bail!("Missing cert");
        };
        let Some(attestation) = cert.attestation else {
            bail!("Missing attestation");
        };
        let app_id = attestation
            .decode_app_id()
            .context("Failed to decode app id")?;
        if app_id != self.remote_app_id {
            bail!("Invalid app id: {}", app_id);
        }
        Ok(())
    }
}

struct Setup<'a> {
    args: &'a TbootArgs,
    local_config: LocalConfig,
    app_compose: AppCompose,
    app_keys: AppKeys,
    encrypted_env: BTreeMap<String, String>,
}

impl<'a> Setup<'a> {
    fn load(args: &'a TbootArgs) -> Result<Self> {
        Ok(Self {
            args,
            local_config: deserialize_json_file(args.resolve("/tapp/config.json"))
                .context("Failed to read config.json")?,
            app_compose: deserialize_json_file(args.resolve("/tapp/app-compose.json"))
                .context("Failed to read app-compose.json")?,
            app_keys: deserialize_json_file(args.resolve("/tapp/appkeys.json"))
                .context("Failed to read appkeys.json")?,
            encrypted_env: deserialize_json_file(args.resolve("/tapp/env.json"))
                .context("Failed to read env.json")?,
        })
    }

    fn resolve(&self, path: &str) -> String {
        self.args.resolve(path)
    }

    async fn setup(&self, nc: &HostApi) -> Result<()> {
        nc.notify_q("boot.progress", "setting up tproxy net").await;
        self.setup_tappd_config()?;
        self.setup_tproxy_net().await?;
        nc.notify_q("boot.progress", "setting up docker").await;
        self.setup_docker_registry()?;
        self.setup_docker_account()?;
        Ok(())
    }

    async fn setup_tproxy_net(&self) -> Result<()> {
        if !self.app_compose.tproxy_enabled() {
            info!("tproxy is not enabled");
            return Ok(());
        }
        if self.app_keys.tproxy_app_id.is_empty() {
            bail!("Missing allowed tproxy app id");
        }

        info!("Setting up tproxy network");
        // Generate WireGuard keys
        let sk = cmd!(wg genkey)?;
        let pk = cmd!(echo $sk | wg pubkey).or(Err(anyhow!("Failed to generate public key")))?;

        // Read config and make API call
        let tproxy_url = self
            .local_config
            .tproxy_url
            .as_ref()
            .context("Missing tproxy_url")?;

        let url = format!("{}/prpc", tproxy_url);
        let ra_validator = RaValidator {
            remote_app_id: self.app_keys.tproxy_app_id.clone(),
        };
        let cert_client =
            CertRequestClient::create(&self.app_keys, self.local_config.pccs_url.as_deref())
                .await
                .context("Failed to create cert client")?;
        let client_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("Failed to generate key")?;
        let config = CertConfig {
            org_name: None,
            subject: "tappd".to_string(),
            subject_alt_names: vec![],
            usage_server_auth: false,
            usage_client_auth: true,
            ext_quote: true,
        };
        let client_certs = cert_client
            .request_cert(&client_key, config)
            .await
            .context("Failed to request cert")?;
        let client_cert = client_certs.join("\n");
        let ca_cert = self.app_keys.ca_cert.clone();
        let client = RaClientConfig::builder()
            .remote_uri(url)
            .maybe_pccs_url(self.local_config.pccs_url.clone())
            .tls_client_cert(client_cert)
            .tls_client_key(client_key.serialize_pem())
            .tls_ca_cert(ca_cert)
            .tls_built_in_root_certs(false)
            .tls_no_check(self.app_keys.tproxy_app_id == "any")
            .cert_validator(Box::new(move |cert| ra_validator.validate(cert)))
            .build()
            .into_client()
            .context("Failed to create RA client")?;
        let tproxy_client = TproxyClient::new(client);
        let response = tproxy_client
            .register_cvm(RegisterCvmRequest {
                client_public_key: pk.to_string(),
            })
            .await
            .context("Failed to register CVM")?;
        let wg_info = response.wg.context("Missing wg info")?;
        let _tappd_info = response.tappd.context("Missing tappd info")?;

        let client_ip = &wg_info.client_ip;
        let server_endpoint = &wg_info.server_endpoint;
        let server_public_key = &wg_info.server_public_key;
        let server_ip = &wg_info.server_ip;

        // Create WireGuard config
        fs::create_dir_all(self.resolve("/etc/wireguard"))?;
        let wg_listen_port = "9182";
        let config = format!(
            "[Interface]\n\
            PrivateKey = {sk}\n\
            ListenPort = {wg_listen_port}\n\
            Address = {client_ip}/32\n\n\
            [Peer]\n\
            PublicKey = {server_public_key}\n\
            AllowedIPs = {server_ip}/32\n\
            Endpoint = {server_endpoint}\n\
            PersistentKeepalive = 25\n"
        );
        fs::write(self.resolve("/etc/wireguard/wg0.conf"), config)?;
        // Add iptables rule to only allow packets from the WireGuard endpoint
        let endpoint_ip = server_endpoint
            .split(':')
            .next()
            .context("Invalid wireguard endpoint")?;
        cmd!(iptables -A INPUT -p udp --dport $wg_listen_port ! -s $endpoint_ip -j DROP)?;

        info!("Starting WireGuard");
        cmd!(wg-quick up wg0)?;
        Ok(())
    }

    fn setup_tappd_config(&self) -> Result<()> {
        info!("Setting up tappd config");
        let config = serde_json::json!({
            "default": {
                "core": {
                    "app_name": self.app_compose.name,
                    "public_logs": self.app_compose.public_logs,
                    "public_sysinfo": self.app_compose.public_sysinfo,
                    "pccs_url": self.local_config.pccs_url,
                }
            }
        });
        let tappd_config = self.resolve("/tapp/tappd.json");
        fs::write(tappd_config, serde_json::to_string_pretty(&config)?)?;
        Ok(())
    }

    fn setup_docker_registry(&self) -> Result<()> {
        info!("Setting up docker registry");
        let registry_url = self
            .app_compose
            .docker_config
            .registry
            .as_deref()
            .unwrap_or_default();
        let registry_url = if registry_url.is_empty() {
            self.local_config
                .docker_registry
                .as_deref()
                .unwrap_or_default()
        } else {
            registry_url
        };
        if registry_url.is_empty() {
            return Ok(());
        }
        info!("Docker registry: {}", registry_url);
        const DAEMON_ENV_FILE: &str = "/etc/docker/daemon.json";
        let mut daemon_env: Value = if fs::metadata(DAEMON_ENV_FILE).is_ok() {
            let daemon_env = fs::read_to_string(DAEMON_ENV_FILE)?;
            serde_json::from_str(&daemon_env).context("Failed to parse daemon.json")?
        } else {
            serde_json::json!({})
        };
        if !daemon_env.is_object() {
            bail!("Invalid daemon.json");
        }
        daemon_env["registry-mirrors"] =
            Value::Array(vec![serde_json::Value::String(registry_url.to_string())]);
        fs::write(DAEMON_ENV_FILE, serde_json::to_string(&daemon_env)?)?;
        Ok(())
    }

    fn setup_docker_account(&self) -> Result<()> {
        info!("Setting up docker account");
        let username = self
            .app_compose
            .docker_config
            .username
            .as_deref()
            .unwrap_or_default();
        if username.is_empty() {
            return Ok(());
        }
        let token_key = self
            .app_compose
            .docker_config
            .token_key
            .as_deref()
            .unwrap_or_default();
        if token_key.is_empty() {
            return Ok(());
        }
        let token = self
            .encrypted_env
            .get(token_key)
            .with_context(|| format!("Missing token for {username}"))?;
        if token.is_empty() {
            bail!("Missing token for {username}");
        }
        cmd!(docker login -u $username -p $token)?;
        Ok(())
    }
}

pub async fn tboot(args: &TbootArgs) -> Result<()> {
    let nc = HostApi::load_or_default(None).unwrap_or_default();
    if let Err(err) = tboot_inner(args, &nc).await {
        nc.notify_q("boot.error", &format!("{err:?}")).await;
        return Err(err);
    }
    Ok(())
}

pub async fn tboot_inner(args: &TbootArgs, nc: &HostApi) -> Result<()> {
    nc.notify_q("boot.progress", "enter system").await;
    Setup::load(args)?.setup(nc).await?;
    Ok(())
}
