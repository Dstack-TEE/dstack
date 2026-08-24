// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    io::Write as _,
    ops::Deref,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use dstack_attest::{default_verifier, emit_runtime_event, set_runtime_event_version};
use dstack_kms_rpc as rpc;
use dstack_types::{
    gpu_policy_hash,
    shared_filenames::{
        APP_COMPOSE, APP_KEYS, DECRYPTED_ENV, DECRYPTED_ENV_JSON, ENCRYPTED_ENV,
        HOST_SHARED_DIR_NAME, INSTANCE_INFO, SYS_CONFIG, USER_CONFIG,
    },
    GpuPolicy, KeyProvider, KeyProviderInfo, GPU_ATTESTATION_OUTPUT,
};
use fs_err as fs;
use luks2::{
    LuksAf, LuksConfig, LuksDigest, LuksHeader, LuksJson, LuksKdf, LuksKeyslot, LuksSegment,
    LuksSegmentSize,
};
use ra_rpc::{
    client::{CertInfo, RaClient, RaClientConfig},
    Attestation,
};
use ra_tls::{
    attestation::{detect_tee_variant, AttestationVerifier, QuoteContentType, TeeVariant},
    cert::{generate_ra_cert, CertConfigV2, CertSigningRequestV2, Csr},
};
use rand::Rng as _;
use safe_write::{safe_write, safe_write_with_mode};
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    cmd_show_mrs,
    crypto::dh_decrypt,
    gen_app_keys_from_seed,
    host_api::HostApi,
    host_shared::{mount_host_shared, unmount_host_shared},
    utils::{
        deserialize_json_file, sha256, sha256_file, AppCompose, AppKeys, KeyProviderKind, SysConfig,
    },
};
use cert_client::CertRequestClient;
use cmd_lib::run_fun as cmd;
use dstack_gateway_rpc::{
    gateway_client::GatewayClient, PortAttrs as RpcPortAttrs, PortPolicy as RpcPortPolicy,
    RegisterCvmRequest, RegisterCvmResponse, WireGuardPeer,
};
use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_human_bytes as hex_bytes;
use serde_json::Value;
use tpm_attest::{self as tpm, TpmContext};

fn attestation_verifier(sys_config: &SysConfig) -> Result<Arc<AttestationVerifier>> {
    Ok(Arc::new(default_verifier(&sys_config.collateral_urls())?))
}

async fn sign_cert_request(
    cert_client: &CertRequestClient,
    key: &KeyPair,
    config: CertConfigV2,
) -> Result<Vec<String>> {
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let attestation = Attestation::quote(&report_data)
        .context("Failed to get quote for cert pubkey")?
        .into_versioned();
    let csr = CertSigningRequestV2 {
        confirm: "please sign cert:".to_string(),
        pubkey,
        config,
        attestation,
    };
    let signature = csr.signed_by(key).context("Failed to sign the CSR")?;
    cert_client
        .sign_csr(&csr, &signature)
        .await
        .context("Failed to sign the CSR")
}

mod config_id_verifier;

#[derive(clap::Parser)]
/// Prepare full disk encryption
pub struct SetupArgs {
    /// dstack work directory
    #[arg(long)]
    work_dir: PathBuf,
    /// Hard disk device
    #[arg(long)]
    device: PathBuf,
    /// The FS mount point
    #[arg(long)]
    mount_point: PathBuf,
}

#[derive(clap::Parser)]
/// Refresh dstack gateway configuration
pub struct GatewayRefreshArgs {
    /// dstack work directory
    #[arg(long)]
    work_dir: PathBuf,
    /// Force reconfiguration even if config unchanged
    #[arg(long)]
    force: bool,
}

#[derive(Deserialize, Serialize, Clone, Default)]
struct InstanceInfo {
    #[serde(with = "hex_bytes", default)]
    instance_id_seed: Vec<u8>,
    #[serde(with = "hex_bytes", default)]
    instance_id: Vec<u8>,
    #[serde(with = "hex_bytes", default)]
    app_id: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
enum FsType {
    #[default]
    Zfs,
    Ext4,
}

impl Display for FsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsType::Zfs => write!(f, "zfs"),
            FsType::Ext4 => write!(f, "ext4"),
        }
    }
}

impl FromStr for FsType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "zfs" => Ok(FsType::Zfs),
            "ext4" => Ok(FsType::Ext4),
            _ => bail!("Invalid filesystem type: {s}, supported types: zfs, ext4"),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DstackOptions {
    storage_encrypted: bool,
    storage_fs: FsType,
}

fn parse_dstack_options(shared: &HostShared) -> Result<DstackOptions> {
    let cmdline = fs::read_to_string("/proc/cmdline").context("Failed to read /proc/cmdline")?;

    let mut options = DstackOptions {
        storage_encrypted: true, // Default to encryption enabled
        storage_fs: FsType::Zfs, // Default to ZFS
    };

    for param in cmdline.split_whitespace() {
        if let Some(value) = param.strip_prefix("dstack.storage_encrypted=") {
            match value {
                "0" | "false" | "no" | "off" => options.storage_encrypted = false,
                "1" | "true" | "yes" | "on" => options.storage_encrypted = true,
                _ => {
                    bail!("Invalid value for dstack.storage_encrypted: {value}");
                }
            }
        } else if let Some(value) = param.strip_prefix("dstack.storage_fs=") {
            options.storage_fs = value.parse().context("Failed to parse dstack.storage_fs")?;
        }
    }

    if let Some(fs) = &shared.app_compose.storage_fs {
        options.storage_fs = fs.parse().context("Failed to parse storage_fs")?;
    }
    Ok(options)
}

#[derive(Clone)]
pub struct HostShareDir {
    base_dir: PathBuf,
}

impl Deref for HostShareDir {
    type Target = PathBuf;
    fn deref(&self) -> &Self::Target {
        &self.base_dir
    }
}

impl From<&Path> for HostShareDir {
    fn from(host_shared_dir: &Path) -> Self {
        Self::new(host_shared_dir)
    }
}

impl HostShareDir {
    fn new(host_shared_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: host_shared_dir.as_ref().to_path_buf(),
        }
    }

    fn app_compose_file(&self) -> PathBuf {
        self.base_dir.join(APP_COMPOSE)
    }

    fn encrypted_env_file(&self) -> PathBuf {
        self.base_dir.join(ENCRYPTED_ENV)
    }

    fn sys_config_file(&self) -> PathBuf {
        self.base_dir.join(SYS_CONFIG)
    }

    fn instance_info_file(&self) -> PathBuf {
        self.base_dir.join(INSTANCE_INFO)
    }

    fn user_config_file(&self) -> PathBuf {
        self.base_dir.join(USER_CONFIG)
    }
}

struct HostShared {
    dir: HostShareDir,
    sys_config: SysConfig,
    app_compose: AppCompose,
    encrypted_env: Vec<u8>,
    instance_info: InstanceInfo,
}

impl HostShared {
    fn load(host_shared_dir: impl Into<HostShareDir>) -> Result<Self> {
        let host_shared_dir = host_shared_dir.into();
        let sys_config = deserialize_json_file(host_shared_dir.sys_config_file())?;
        let app_compose = deserialize_json_file(host_shared_dir.app_compose_file())?;
        let instance_info_file = host_shared_dir.instance_info_file();
        let instance_info = if instance_info_file.exists() {
            deserialize_json_file(instance_info_file)?
        } else {
            InstanceInfo::default()
        };
        let encrypted_env = fs::read(host_shared_dir.encrypted_env_file()).unwrap_or_default();
        Ok(Self {
            dir: host_shared_dir.clone(),
            sys_config,
            app_compose,
            encrypted_env,
            instance_info,
        })
    }

    fn copy(host_shared_dir: &Path, host_shared_copy_dir: &Path) -> Result<HostShared> {
        const SZ_1KB: u64 = 1024;
        const SZ_1MB: u64 = 1024 * SZ_1KB;

        let copy = |src: &str, max_size: u64, ignore_missing: bool| -> Result<()> {
            let src_path = host_shared_dir.join(src);
            let dst_path = host_shared_copy_dir.join(src);
            if !src_path.exists() {
                if ignore_missing {
                    return Ok(());
                }
                bail!("Source file {src} does not exist");
            }
            let src_size = src_path.metadata()?.len();
            if src_size > max_size {
                bail!("Source file {src} is too large, max size is {max_size} bytes");
            }
            use fs::os::unix::fs::OpenOptionsExt;
            let mut src_io = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(src_path)?;
            let mut dst_io = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(dst_path)?;
            std::io::copy(&mut src_io, &mut dst_io)?;
            Ok(())
        };
        info!("Mounting host-shared");
        mount_host_shared(host_shared_dir)?;

        cmd! {
            mkdir -p $host_shared_copy_dir;
            info "Copying host-shared files";
        }?;
        copy(APP_COMPOSE, SZ_1MB * 50, false)?;
        copy(SYS_CONFIG, SZ_1KB * 32, false)?;
        copy(INSTANCE_INFO, SZ_1KB * 10, true)?;
        copy(ENCRYPTED_ENV, SZ_1KB * 256, true)?;
        copy(USER_CONFIG, SZ_1MB * 50, true)?;
        info!("Unmounting host-shared");
        unmount_host_shared(host_shared_dir)?;
        HostShared::load(host_shared_copy_dir)
    }
}

const GATEWAY_CACHE_PATH: &str = "/run/dstack/gateway-cache.json";
const GATEWAY_CACHE_PREFIX: &str = "/run/dstack/gateway-cache-";
/// Certificate validity period in seconds (10 days)
const CERT_VALIDITY_SECS: u64 = 10 * 24 * 3600;
const MAX_SUPPORTED_MANIFEST_VERSION: u32 = 3;
const MANIFEST_VERSION_3: u32 = 3;

#[derive(Serialize, Deserialize, Clone)]
struct GatewayKeyStore {
    /// Client certificate chain
    client_cert: String,
    /// Client certificate chain with quote
    client_cert_with_quote: String,
    /// Client private key
    client_key: String,
    /// Certificate expiry time as seconds since UNIX epoch
    cert_not_after: u64,
    /// WireGuard private key
    wg_sk: String,
    /// WireGuard public key
    wg_pk: String,
    /// The gateway URL that last accepted a registration for this cluster.
    ///
    /// Tried first on the next refresh. Without it the list is walked in
    /// configured order every time, which is sticky in the wrong way: every CVM
    /// piles onto the first URL, and when that one has an outage the whole
    /// fleet moves to the second and then moves *back* the moment the first
    /// recovers. Each of those moves rewrites the instance record from a
    /// different node's memory, which is exactly what loses per-instance state
    /// that only lives there.
    ///
    /// Scoped to a boot, because the cache is on tmpfs. That is the right
    /// scope: a boot regenerates the WireGuard key and re-registers from
    /// scratch anyway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_url: Option<String>,
}

/// Freshly issued client certificate material for [`GatewayKeyStore::renewed`].
struct IssuedClientCerts {
    client_cert: String,
    client_cert_with_quote: String,
    client_key: String,
    cert_not_after: u64,
}

impl GatewayKeyStore {
    /// The store a certificate renewal produces: fresh certificates plus
    /// everything the renewal must carry over from the previous cache — the
    /// WireGuard identity, because the gateway maps this peer by its public
    /// key, and the registration preference, because the renewed store is
    /// saved over the cache before the per-cluster loop reads the preference
    /// back, so dropping it here would drop it on disk too and drift the
    /// fleet back onto the first configured URL at every renewal.
    fn renewed(
        cache: Option<Self>,
        generate_wg: impl FnOnce() -> Result<(String, String)>,
        certs: IssuedClientCerts,
    ) -> Result<Self> {
        let (wg_sk, wg_pk, last_url) = match cache {
            Some(cache) => {
                info!("reusing cached WireGuard keys");
                (cache.wg_sk, cache.wg_pk, cache.last_url)
            }
            None => {
                let (wg_sk, wg_pk) = generate_wg()?;
                (wg_sk, wg_pk, None)
            }
        };
        Ok(Self {
            client_cert: certs.client_cert,
            client_cert_with_quote: certs.client_cert_with_quote,
            client_key: certs.client_key,
            cert_not_after: certs.cert_not_after,
            wg_sk,
            wg_pk,
            last_url,
        })
    }

    fn load_from(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn load_from_default() -> Option<Self> {
        Self::load_from(Path::new(GATEWAY_CACHE_PATH))
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string(self).context("Failed to serialize gateway cache")?;
        safe_write_with_mode(path, &content, 0o600).context("Failed to write gateway cache")?;
        Ok(())
    }

    fn save_to_default(&self) -> Result<()> {
        self.save_to(Path::new(GATEWAY_CACHE_PATH))
    }

    fn is_cert_valid_at(&self, now: u64) -> bool {
        // Valid if at least 10 minutes remaining.
        now.saturating_add(600) < self.cert_not_after
    }

    fn is_cert_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.is_cert_valid_at(now)
    }
}

fn gateway_rpc_url(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/prpc") {
        base.to_string()
    } else {
        format!("{base}/prpc")
    }
}

#[derive(Debug)]
struct GatewayTarget {
    name: String,
    urls: Vec<String>,
}

struct PreparedGatewayCluster {
    name: String,
    index: usize,
    key_store: GatewayKeyStore,
    response: RegisterCvmResponse,
}

fn wireguard_endpoint_hosts(config: &str) -> Result<Vec<String>> {
    config
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Endpoint = "))
        .map(|endpoint| {
            endpoint
                .rsplit_once(':')
                .map(|(host, _)| host.trim_matches(['[', ']']).to_string())
                .context("invalid WireGuard endpoint")
        })
        .collect()
}

fn remove_partial_wireguard_config(path: &str, cluster: &str) {
    if let Err(error) = fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            warn!(
                cluster = cluster,
                "failed to remove partially applied WireGuard config: {error}"
            );
        }
    }
}

struct GatewayContext<'a> {
    shared: &'a HostShared,
    keys: &'a AppKeys,
}

impl<'a> GatewayContext<'a> {
    fn new(shared: &'a HostShared, keys: &'a AppKeys) -> Self {
        Self { shared, keys }
    }

    #[errify::errify("Failed to create gateway client for {gateway_url}")]
    fn create_gateway_client(
        &self,
        gateway_url: &str,
        client_key: &str,
        client_cert: &str,
        gateway_app_id: &str,
    ) -> Result<GatewayClient<RaClient>> {
        let url = gateway_rpc_url(gateway_url);
        let ca_cert = self.keys.ca_cert.clone();
        let cert_validator = AppIdValidator {
            allowed_app_id: gateway_app_id.to_string(),
        };
        let client = RaClientConfig::builder()
            .remote_uri(url)
            .tls_client_cert(client_cert.to_string())
            .tls_client_key(client_key.to_string())
            .tls_ca_cert(ca_cert)
            .tls_built_in_root_certs(false)
            .tls_no_check(gateway_app_id == "any")
            .verify_server_attestation(false)
            .cert_validator(Box::new(move |cert| cert_validator.validate(cert)))
            .build()
            .into_client()
            .context("Failed to create RA client")?;
        Ok(GatewayClient::new(client))
    }

    async fn register_cvm(
        &self,
        gateway_url: &str,
        key_store: &GatewayKeyStore,
        gateway_app_id: &str,
    ) -> Result<RegisterCvmResponse> {
        let port_policy = RpcPortPolicy {
            ports: self
                .shared
                .app_compose
                .port_policy
                .ports
                .iter()
                .map(|p| RpcPortAttrs {
                    port: p.port as u32,
                    pp: p.pp,
                })
                .collect(),
            restrict_mode: self.shared.app_compose.port_policy.restrict_mode,
        };
        let health_check = health_check_requested(&self.shared.app_compose);
        let client = self.create_gateway_client(
            gateway_url,
            &key_store.client_key,
            &key_store.client_cert,
            gateway_app_id,
        )?;
        let result = client
            .register_cvm(RegisterCvmRequest {
                client_public_key: key_store.wg_pk.clone(),
                port_policy: Some(port_policy.clone()),
                health_check,
            })
            .await
            .context("Failed to register CVM");
        let Err(err) = &result else {
            return result;
        };
        // If the error contains "no attestation provided", it's likely an older gateway version
        let is_legacy_gateway = format!("{err:#}").contains("no attestation provided");
        if !is_legacy_gateway {
            return result;
        }
        info!("Seems like the gateway is an older version, retrying with quote cert");
        let client = self.create_gateway_client(
            gateway_url,
            &key_store.client_key,
            &key_store.client_cert_with_quote,
            gateway_app_id,
        )?;
        client
            .register_cvm(RegisterCvmRequest {
                client_public_key: key_store.wg_pk.clone(),
                port_policy: Some(port_policy),
                health_check,
            })
            .await
            .context("Failed to register CVM")
    }

    async fn get_or_generate_key_store(&self) -> Result<GatewayKeyStore> {
        // Try to load existing cache
        let cache = GatewayKeyStore::load_from_default();

        // If cache is fully valid, return it
        if let Some(ref cache) = cache {
            if cache.is_cert_valid() {
                info!("Using cached gateway key store");
                return Ok(cache.clone());
            }
        }

        // Request new client certificates
        info!("Requesting new client certificates");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cert_not_after = now + CERT_VALIDITY_SECS;
        let verifier = attestation_verifier(&self.shared.sys_config)?;
        let cert_client = CertRequestClient::create(
            self.keys,
            verifier,
            self.shared.sys_config.vm_config.clone(),
        )
        .await
        .context("Failed to create cert client")?;
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("Failed to generate key")?;

        // Request certificate without quote (for new gateways)
        let config = CertConfigV2 {
            org_name: None,
            subject: "dstack-guest-agent".to_string(),
            subject_alt_names: vec![],
            usage_server_auth: false,
            usage_client_auth: true,
            ext_quote: false,
            ext_app_info: true,
            not_before: None,
            not_after: Some(cert_not_after),
        };
        let certs = sign_cert_request(&cert_client, &key, config)
            .await
            .context("Failed to request cert")?;
        let client_cert = certs.join("\n");
        let client_key = key.serialize_pem();

        // Request certificate with quote (for pre-0.5.6 gateways)
        // TODO: Remove this once pre-0.5.6 gateways are deprecated
        let config_with_quote = CertConfigV2 {
            org_name: None,
            subject: "dstack-guest-agent".to_string(),
            subject_alt_names: vec![],
            usage_server_auth: false,
            usage_client_auth: true,
            ext_quote: true,
            ext_app_info: true,
            not_before: None,
            not_after: Some(cert_not_after),
        };
        let certs_with_quote = sign_cert_request(&cert_client, &key, config_with_quote)
            .await
            .context("Failed to request cert with quote")?;
        let client_cert_with_quote = certs_with_quote.join("\n");

        GatewayKeyStore::renewed(
            cache,
            || {
                info!("generating new WireGuard keys");
                let sk = cmd!(wg genkey)?;
                let pk =
                    cmd!(echo $sk | wg pubkey).or(Err(anyhow!("Failed to generate public key")))?;
                Ok((sk, pk))
            },
            IssuedClientCerts {
                client_cert,
                client_cert_with_quote,
                client_key,
                cert_not_after,
            },
        )
    }

    fn key_store_for_additional_cluster(
        &self,
        name: &str,
        certificate_source: &GatewayKeyStore,
    ) -> Result<(GatewayKeyStore, PathBuf)> {
        let path = PathBuf::from(format!("{GATEWAY_CACHE_PREFIX}{name}.json"));
        if let Some(cache) = GatewayKeyStore::load_from(&path) {
            if cache.is_cert_valid() {
                info!(cluster = name, "Using cached gateway cluster key store");
                return Ok((cache, path));
            }
        }
        let old = GatewayKeyStore::load_from(&path);
        let (wg_sk, wg_pk) = if let Some(old) = old {
            (old.wg_sk, old.wg_pk)
        } else {
            let sk = cmd!(wg genkey)?;
            let pk =
                cmd!(echo $sk | wg pubkey).or(Err(anyhow!("Failed to generate public key")))?;
            (sk, pk)
        };
        let mut key_store = certificate_source.clone();
        key_store.wg_sk = wg_sk;
        key_store.wg_pk = wg_pk;
        Ok((key_store, path))
    }

    async fn setup(&self, force: bool) -> Result<()> {
        if !self.shared.app_compose.gateway_enabled() {
            info!("dstack-gateway is not enabled");
            return Ok(());
        }
        if self.keys.gateway_app_id.is_empty() {
            bail!("Missing allowed dstack-gateway app id");
        }

        let targets = self.gateway_targets()?;
        let uses_explicit_clusters = !self.shared.sys_config.gateway_clusters.is_empty();
        info!(clusters = targets.len(), "Setting up dstack-gateway");

        // Certificates are valid for every gateway identity authorized by KMS,
        // while each cluster receives a distinct WireGuard identity.
        let primary_key_store = self.get_or_generate_key_store().await?;
        if let Err(err) = primary_key_store.save_to_default() {
            warn!("failed to save gateway cache: {err:?}");
        }

        let mut errors = Vec::new();
        for (index, target) in targets.iter().enumerate() {
            let key_store_result = if index == 0 && !uses_explicit_clusters {
                Ok((primary_key_store.clone(), PathBuf::from(GATEWAY_CACHE_PATH)))
            } else {
                self.key_store_for_additional_cluster(&target.name, &primary_key_store)
            };
            let (mut key_store, cache_path) = match key_store_result {
                Ok(value) => value,
                Err(err) => {
                    errors.push(format!("{}: {err:#}", target.name));
                    continue;
                }
            };
            carry_cluster_preference(&mut key_store, &cache_path, &target.urls);
            if let Err(err) = key_store.save_to(&cache_path) {
                warn!(cluster = %target.name, "failed to save gateway cluster cache: {err:?}");
            }

            let mut first_error = None;
            let mut response = None;
            let mut accepted_by = None;
            for url in order_by_stickiness(&target.urls, key_store.last_url.as_deref()) {
                match self
                    .register_cvm(url, &key_store, &self.keys.gateway_app_id)
                    .await
                {
                    Ok(value) => {
                        response = Some(value);
                        accepted_by = Some(url.clone());
                        break;
                    }
                    Err(err) => {
                        warn!(cluster = %target.name, %url, "Failed to register CVM: {err:?}");
                        if first_error.is_none() {
                            first_error = Some(err);
                        }
                    }
                }
            }
            record_accepting_url(&target.name, &mut key_store, &cache_path, accepted_by);
            let Some(response) = response else {
                errors.push(format!(
                    "{}: {:#}",
                    target.name,
                    first_error.unwrap_or_else(|| anyhow!("no gateway URLs configured"))
                ));
                continue;
            };
            let cluster = PreparedGatewayCluster {
                name: target.name.clone(),
                index,
                key_store,
                response,
            };
            if let Err(err) = self.apply_wireguard(cluster, force) {
                errors.push(format!("{}: {err:#}", target.name));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("failed to refresh gateway clusters: {}", errors.join("; "))
        }
    }

    fn gateway_targets(&self) -> Result<Vec<GatewayTarget>> {
        if !self.shared.sys_config.gateway_urls.is_empty()
            && !self.shared.sys_config.gateway_clusters.is_empty()
        {
            warn!("both gateway_urls and gateway_clusters are configured; ignoring gateway_urls");
        }
        let targets = if self.shared.sys_config.gateway_clusters.is_empty() {
            vec![GatewayTarget {
                name: "default".to_string(),
                urls: self.shared.sys_config.gateway_urls.clone(),
            }]
        } else {
            self.shared
                .sys_config
                .gateway_clusters
                .iter()
                .map(|cluster| GatewayTarget {
                    name: cluster.name.clone(),
                    urls: cluster.urls.clone(),
                })
                .collect()
        };
        let mut names = std::collections::HashSet::new();
        for target in &targets {
            if target.name.is_empty()
                || !target
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            {
                bail!("invalid gateway cluster name: {}", target.name);
            }
            if !names.insert(target.name.as_str()) {
                bail!("duplicate gateway cluster name: {}", target.name);
            }
            if target.urls.is_empty() {
                bail!("gateway cluster {} has no URLs", target.name);
            }
        }
        Ok(targets)
    }

    fn apply_wireguard(&self, mut cluster: PreparedGatewayCluster, force: bool) -> Result<()> {
        let interface = format!("dstack-wg{}", cluster.index);
        let config_path = format!("/etc/wireguard/{interface}.conf");
        let listen_port = 9182_u16
            .checked_add(
                cluster
                    .index
                    .try_into()
                    .context("too many gateway clusters")?,
            )
            .context("too many gateway clusters")?;
        let mut wg_info = cluster.response.wg.take().context("missing wg info")?;
        wg_info.servers.sort_by(|a, b| a.pk.cmp(&b.pk));
        let mut new_config = format!(
            "[Interface]\nPrivateKey = {}\nListenPort = {listen_port}\nAddress = {}/32\n\n",
            cluster.key_store.wg_sk, wg_info.client_ip
        );
        for WireGuardPeer { pk, ip, endpoint } in &wg_info.servers {
            let ip = ip.split('/').next().unwrap_or_default();
            new_config.push_str(&format!(
                "[Peer]\nPublicKey = {pk}\nAllowedIPs = {ip}/32\nEndpoint = {endpoint}\nPersistentKeepalive = 25\n"
            ));
        }
        let old_config = fs::read_to_string(&config_path).ok();
        if !force && old_config.as_ref() == Some(&new_config) {
            info!(cluster = %cluster.name, "WireGuard config unchanged");
            return Ok(());
        }
        let new_endpoints = wireguard_endpoint_hosts(&new_config)?;
        let applied = self.apply_wireguard_config(
            &interface,
            &config_path,
            listen_port,
            &new_config,
            &new_endpoints,
        );
        if let Err(error) = applied {
            // Registration and refresh are independent per cluster. Preserve
            // this cluster's last-known-good config if applying its replacement
            // fails; a cluster with no prior config removes the false marker so
            // the checker takes its fast missing-config retry path.
            if let Some(old_config) = old_config {
                match wireguard_endpoint_hosts(&old_config).and_then(|endpoints| {
                    self.apply_wireguard_config(
                        &interface,
                        &config_path,
                        listen_port,
                        &old_config,
                        &endpoints,
                    )
                }) {
                    Ok(()) => {
                        warn!(cluster = %cluster.name, "restored previous WireGuard config after refresh failure")
                    }
                    Err(rollback_error) => {
                        warn!(cluster = %cluster.name, "failed to restore previous WireGuard config: {rollback_error:#}");
                        remove_partial_wireguard_config(&config_path, &cluster.name);
                    }
                }
            } else {
                remove_partial_wireguard_config(&config_path, &cluster.name);
            }
            return Err(error);
        }
        Ok(())
    }

    fn apply_wireguard_config(
        &self,
        interface: &str,
        config_path: &str,
        listen_port: u16,
        config: &str,
        endpoint_hosts: &[String],
    ) -> Result<()> {
        safe_write_with_mode(config_path, config, 0o600)
            .context("failed to write WireGuard config")?;
        cmd!(ignore wg-quick down $interface)?;

        // Docker also updates iptables throughout boot. Bound every lock wait
        // so a transient xtables.lock holder neither breaks the cluster update
        // nor stalls the checker indefinitely.
        let xtables_wait = "5";
        let chain = format!("DSTACK_WG{}", interface.trim_start_matches("dstack-wg"));
        if interface == "dstack-wg0" {
            // Remove the pre-multi-cluster chain after upgrading. The new
            // per-interface chain below owns the same listen port.
            cmd!(ignore iptables -w $xtables_wait -D INPUT -p udp --dport $listen_port -j DSTACK_WG 2>/dev/null)?;
            cmd!(ignore iptables -w $xtables_wait -F DSTACK_WG 2>/dev/null)?;
            cmd!(ignore iptables -w $xtables_wait -X DSTACK_WG 2>/dev/null)?;
        }
        cmd!(ignore iptables -w $xtables_wait -N $chain 2>/dev/null)?;
        cmd!(iptables -w $xtables_wait -F $chain)?;
        cmd!(ignore iptables -w $xtables_wait -D INPUT -p udp --dport $listen_port -j $chain 2>/dev/null)?;
        cmd!(iptables -w $xtables_wait -I INPUT -p udp --dport $listen_port -j $chain)?;
        for endpoint_host in endpoint_hosts {
            cmd!(iptables -w $xtables_wait -A $chain -s $endpoint_host -j ACCEPT)?;
        }
        cmd!(iptables -w $xtables_wait -A $chain -j DROP)?;
        info!(%interface, "starting WireGuard");
        cmd!(wg-quick up $interface)?;
        Ok(())
    }
}

fn truncate(s: &[u8], len: usize) -> &[u8] {
    if s.len() > len {
        &s[..len]
    } else {
        s
    }
}

/// Return a platform-provided, per-instance value to mix into `instance_id`.
///
/// `instance_id` is normally derived from `instance_id_seed`, which is persisted
/// on the data disk. That makes it unsafe on clouds where a VM can be cloned from
/// a disk image / snapshot: every clone inherits the same seed and therefore the
/// same `instance_id`. To keep `instance_id` unique per running VM we mix in a
/// per-instance value that lives outside the cloneable disk.
///
/// On GCP we use the public key of the pre-provisioned vTPM Attestation Key. On
/// AWS EC2 we create the deterministic endorsement primary key and use its
/// public area. Both values are derived from per-instance TPM state, not from the
/// cloneable data disk, so a disk snapshot launched as a new VM gets a different
/// binding while reboot/stop-start of the same VM keeps it stable. We hash public
/// areas rather than certificates so the binding is immune to certificate
/// re-issuance.
///
/// Returns `Ok(None)` on platforms with no such binding; the `instance_id` then
/// keeps its previous seed-only derivation. Fails closed: if the platform is known
/// to provide a binding but it cannot be read, we error rather than silently fall
/// back to a duplication-prone id.
fn platform_instance_binding() -> Result<Option<Vec<u8>>> {
    use dstack_types::Platform;
    match Platform::detect() {
        Some(Platform::Gcp) => {
            // Prefer the ECC AK, fall back to RSA (matches the quote path).
            let ak = match tpm::load_gcp_ak_ecc(None) {
                Ok(ak) => ak,
                Err(ecc_err) => tpm::load_gcp_ak_rsa(None).with_context(|| {
                    format!("failed to load gcp vTPM AK (ecc error: {ecc_err:#})")
                })?,
            };
            if ak.pub_area.is_empty() {
                bail!("gcp vTPM AK public area is empty");
            }
            Ok(Some(sha256(&ak.pub_area).to_vec()))
        }
        Some(Platform::AwsEc2) => {
            let mut tpm = tpm2::TpmContext::new(None).context("failed to open NitroTPM")?;
            let template = tpm2::TpmtPublic::rsa_ek();
            let (handle, public_area) = tpm
                .create_primary(tpm2::tpm_rh::ENDORSEMENT, &template)
                .context("failed to create NitroTPM endorsement primary key")?;
            let flush_result = tpm.flush_context(handle);
            if public_area.is_empty() {
                bail!("NitroTPM endorsement public area is empty");
            }
            flush_result.context("failed to flush NitroTPM endorsement primary key")?;
            Ok(Some(sha256(&public_area).to_vec()))
        }
        _ => Ok(None),
    }
}

fn emit_key_provider_info(provider_info: &KeyProviderInfo) -> Result<()> {
    info!("Key provider info: {provider_info:?}");
    let provider_info_json = serde_json::to_vec(&provider_info)?;
    emit_runtime_event("key-provider", &provider_info_json)?;
    Ok(())
}

fn verify_manifest_version(app_compose: &AppCompose) -> Result<u32> {
    let manifest_version = app_compose
        .manifest_version_u32()
        .context("Invalid manifest_version")?;
    if manifest_version > MAX_SUPPORTED_MANIFEST_VERSION {
        bail!(
            "Unsupported manifest_version: {manifest_version}, max supported: {MAX_SUPPORTED_MANIFEST_VERSION}"
        );
    }
    Ok(manifest_version)
}

fn verify_app_compose_policy(shared: &HostShared) -> Result<()> {
    let app_compose = &shared.app_compose;
    let sys_config = &shared.sys_config;
    verify_manifest_feature_requirements(app_compose)?;
    let Some(requirements) = app_compose.requirements.as_ref() else {
        return Ok(());
    };
    if let Some(platforms) = requirements.platforms.as_deref() {
        if platforms.is_empty() {
            bail!("Unsupported attestation platform: requirements.platforms is empty");
        }
        let current_platform =
            detect_tee_variant().context("failed to detect current attestation platform")?;
        verify_platform_requirements(app_compose, current_platform)?;
    }
    if requirements.tdx_measure_acpi_tables.is_some() {
        let current_platform =
            detect_tee_variant().context("failed to detect current attestation platform")?;
        verify_tdx_measure_acpi_tables_requirement(
            app_compose,
            &sys_config.vm_config,
            current_platform,
        )?;
    }
    if let Some(launch_token_hash) = requirements.launch_token_hash.as_deref() {
        // Only touch user_config when the requirement is present; otherwise it
        // is opaque application data and must not be parsed here.
        let user_config = fs::read_to_string(shared.dir.user_config_file())
            .context("failed to read user_config for requirements.launch_token_hash")?;
        let token = launch_token_from_user_config(&user_config)?;
        verify_launch_token_requirement(launch_token_hash, &token)?;
    }
    Ok(())
}

/// The order to try a cluster's gateway URLs in, last accepting one first.
///
/// Walking the configured list every time is sticky in the wrong way. Every CVM
/// piles onto the first URL, so one node takes all registration traffic; and
/// when that node has an outage the whole fleet moves to the second URL and
/// then moves *back* the instant the first recovers. Every one of those moves
/// rewrites the instance record from a different node's memory, which is how
/// per-instance state that lives only there gets lost.
///
/// Preferring the last node that accepted turns both into one-time events: a
/// CVM that moved stays moved, and the fleet spreads over the outage rather
/// than snapping back together.
///
/// `last` is only a preference. Everything else still follows in configured
/// order, so a URL that is down costs one failed attempt and nothing more.
fn order_by_stickiness<'a>(urls: &'a [String], last: Option<&str>) -> Vec<&'a String> {
    let mut ordered = Vec::with_capacity(urls.len());
    if let Some(last) = last {
        ordered.extend(urls.iter().filter(|url| url.as_str() == last));
    }
    ordered.extend(urls.iter().filter(|url| Some(url.as_str()) != last));
    ordered
}

/// Carry the cluster's own remembered URL into a freshly resolved key store.
///
/// The preference is per cluster. The store handed in may have just been
/// rebuilt by a certificate renewal, or cloned from the primary's for an
/// additional cluster — either way the preference that counts is the one this
/// cluster's cache holds, and only while the operator still lists the URL: a
/// URL removed from the config is dropped rather than resurrected.
fn carry_cluster_preference(
    key_store: &mut GatewayKeyStore,
    cache_path: &Path,
    configured: &[String],
) {
    key_store.last_url = GatewayKeyStore::load_from(cache_path)
        .and_then(|cached| cached.last_url)
        .filter(|url| configured.iter().any(|configured| configured == url));
}

/// Persist the URL that accepted this round's registration, if it changed.
///
/// Only an acceptance updates the preference. A round where every URL failed
/// says nothing about where the instance record lives, and clearing on it
/// would have one bad tick — a full-cluster outage, or a blip in this CVM's
/// own networking — erase the fleet's spread and pile everyone back onto the
/// first configured URL at recovery.
fn record_accepting_url(
    cluster: &str,
    key_store: &mut GatewayKeyStore,
    cache_path: &Path,
    accepted_by: Option<String>,
) {
    let Some(url) = accepted_by else {
        return;
    };
    if key_store.last_url.as_deref() == Some(url.as_str()) {
        return;
    }
    if key_store.last_url.is_some() {
        info!(cluster, %url, "gateway registration moved");
    }
    key_store.last_url = Some(url);
    if let Err(err) = key_store.save_to(cache_path) {
        warn!(cluster, "failed to record the accepting gateway: {err:?}");
    }
}

/// Whether this app asked the gateway to gate its traffic on health.
///
/// Opt-in, not a build-time fact: the guest agent only refreshes a verdict when
/// the app asked for one, so telling the gateway to poll an app that did not
/// would cost every gateway node a round trip per interval to be told what it
/// already assumes.
///
/// This is the only hop between the app's manifest and the gateway's behaviour,
/// which is why it is a named function rather than an expression inside the
/// registration call: getting it wrong makes the whole feature inert fleet-wide
/// with nothing to show for it.
fn health_check_requested(app_compose: &AppCompose) -> bool {
    app_compose
        .requirements
        .as_ref()
        .is_some_and(|requirements| requirements.health_check)
}

fn verify_manifest_feature_requirements(app_compose: &AppCompose) -> Result<()> {
    let manifest_version = verify_manifest_version(app_compose)?;
    if app_compose.requirements.is_some() && manifest_version < MANIFEST_VERSION_3 {
        bail!(
            "requirements requires manifest_version >= {MANIFEST_VERSION_3}; use string manifest_version \"{MANIFEST_VERSION_3}\" so older guests fail closed"
        );
    }
    if app_compose.runner == "nerdctl-compose" && manifest_version < MANIFEST_VERSION_3 {
        bail!(
            "nerdctl-compose requires manifest_version >= {MANIFEST_VERSION_3}; use string manifest_version \"{MANIFEST_VERSION_3}\" so older guests fail closed"
        );
    }
    if app_compose.init_script.len() > 1 && manifest_version < MANIFEST_VERSION_3 {
        bail!(
            "multiple init scripts require manifest_version >= {MANIFEST_VERSION_3}; use string manifest_version \"{MANIFEST_VERSION_3}\" so older guests fail closed"
        );
    }
    if app_compose.runner != "nerdctl-compose" && app_compose.snapshotter.is_some() {
        bail!("snapshotter is only supported by the nerdctl-compose runner");
    }
    verify_health_check_requirement(app_compose)?;
    Ok(())
}

/// Reject a health-gating request this guest could not act on.
///
/// Only checks that need nothing but the manifest. The obvious third
/// check -- "does any service actually declare a `healthcheck:`?" -- is
/// deliberately *not* here, even though an app whose containers declare none
/// reports healthy forever, which is the failure this is meant to remove.
///
/// It is not here because at this point the only thing available is the raw
/// compose text, and reading it is not the same question as the one the runtime
/// answers. Scanning YAML for the key misses a `HEALTHCHECK` in the Dockerfile,
/// misses a `<<:` merge from a shared anchor (the loader does not expand merge
/// keys, so the service reads as having no `healthcheck` at all), misses
/// `extends:` and multi-file overrides -- and *passes* `healthcheck: {disable:
/// true}` and `test: ["NONE"]`, which are exactly the configurations that
/// produce no verdict at runtime. It rejects working deployments and admits
/// broken ones.
///
/// The guest agent asks the runtime instead, which is the authority, and
/// reports "nothing here can be judged" as unhealthy-with-a-reason. That
/// surfaces in the gateway log and on the dashboard rather than as a boot
/// failure, and it is right in all of the cases above.
fn verify_health_check_requirement(app_compose: &AppCompose) -> Result<()> {
    let Some(requirements) = app_compose.requirements.as_ref() else {
        return Ok(());
    };
    if !requirements.health_check {
        // A path without gating enabled is inert, not an error: an operator
        // turning gating off during an incident should not have to also delete
        // the path they will want back.
        return Ok(());
    }
    match requirements.health_status_file.as_deref() {
        Some(path) => {
            if !path.starts_with('/') {
                bail!("requirements.health_status_file must be an absolute path: {path}");
            }
        }
        None => {
            // The container fallback has nothing to look at for a runner that
            // starts no containers, so it would answer "healthy" unconditionally.
            if app_compose.runner != "docker-compose" && app_compose.runner != "nerdctl-compose" {
                bail!(
                    "requirements.health_check needs health_status_file for the {} runner; \
                     without containers to inspect there is nothing to judge",
                    app_compose.runner
                );
            }
        }
    }
    Ok(())
}

fn verify_platform_requirements(
    app_compose: &AppCompose,
    current_platform: TeeVariant,
) -> Result<()> {
    let Some(requirements) = app_compose.requirements.as_ref() else {
        return Ok(());
    };
    let Some(allowed_platforms) = requirements.platforms.as_deref() else {
        return Ok(());
    };
    let allowed_modes = allowed_platforms
        .iter()
        .enumerate()
        .map(|(index, platform)| parse_requirement_platform(platform, index))
        .collect::<Result<Vec<_>>>()?;
    if allowed_modes.contains(&current_platform) {
        info!(
            "platform requirement satisfied: current={}, allowed=[{}]",
            current_platform.as_str(),
            format_requirement_platforms(allowed_platforms)
        );
        return Ok(());
    }
    bail!(
        "Unsupported attestation platform: current {}, allowed [{}]",
        current_platform.as_str(),
        format_requirement_platforms(allowed_platforms)
    );
}

fn parse_requirement_platform(platform: &str, index: usize) -> Result<TeeVariant> {
    serde_json::from_value(serde_json::Value::String(platform.to_string()))
        .with_context(|| format!("Invalid requirements.platforms[{index}]: {platform}"))
}

fn format_requirement_platforms(platforms: &[String]) -> String {
    platforms.join(", ")
}

fn verify_tdx_measure_acpi_tables_requirement(
    app_compose: &AppCompose,
    vm_config: &str,
    current_platform: TeeVariant,
) -> Result<()> {
    let Some(measure_acpi_tables) = app_compose
        .requirements
        .as_ref()
        .and_then(|requirements| requirements.tdx_measure_acpi_tables)
    else {
        return Ok(());
    };
    if current_platform != TeeVariant::DstackTdx {
        return Ok(());
    }
    let vm_config: dstack_types::VmConfig = serde_json::from_str(vm_config)
        .context("failed to parse vm_config for requirements.tdx_measure_acpi_tables")?;
    let uses_lite = vm_config.tdx_attestation_variant.is_lite();
    if measure_acpi_tables && uses_lite {
        bail!(
            "unsupported TDX attestation mode: requirements.tdx_measure_acpi_tables=true requires ACPI table measurement"
        );
    }
    if !measure_acpi_tables && !uses_lite {
        bail!(
            "unsupported TDX attestation mode: requirements.tdx_measure_acpi_tables=false requires TDX lite attestation"
        );
    }
    info!(
        "tdx ACPI table measurement requirement satisfied: measure_acpi_tables={}",
        measure_acpi_tables
    );
    Ok(())
}

/// Minimum launch token length in bytes. `launch_token_hash` is public (it is
/// part of app-compose.json), so short tokens can be recovered offline via
/// brute force or precomputed tables. Length cannot prove entropy, but it
/// rejects the trivially guessable tokens; deployers should still generate
/// random tokens (e.g. 32 random alphanumeric characters).
const LAUNCH_TOKEN_MIN_LEN: usize = 32;

/// Enforce the launch-token pattern: the compose-hash-measured
/// `requirements.launch_token_hash` must match the domain-separated digest of
/// the launch token (see [`dstack_types::launch_token_hash`]). This binds a
/// deployment to a token known only to the deployer, so a host cannot launch
/// the app with substituted inputs.
fn verify_launch_token_requirement(launch_token_hash: &str, token: &str) -> Result<()> {
    let expected = hex::decode(launch_token_hash)
        .context("invalid requirements.launch_token_hash: not a hex string")?;
    if expected.len() != 32 {
        bail!(
            "invalid requirements.launch_token_hash: expected 32-byte sha256 hex, got {} bytes",
            expected.len()
        );
    }
    if token.len() < LAUNCH_TOKEN_MIN_LEN {
        bail!(
            "launch token too short: got {} bytes, minimum is {LAUNCH_TOKEN_MIN_LEN}; use a random token since launch_token_hash is public",
            token.len()
        );
    }
    if dstack_types::launch_token_hash(token)[..] != expected[..] {
        bail!("launch token mismatch: sha256(\"{}\" || launch token) does not match requirements.launch_token_hash", dstack_types::LAUNCH_TOKEN_HASH_DOMAIN);
    }
    info!("launch token requirement satisfied");
    Ok(())
}

/// Extract the launch token from `user_config` at JSON path
/// `dstack.launch_token`. Callers must only invoke this when
/// `requirements.launch_token_hash` is set; otherwise `user_config` is opaque
/// application data and must not be parsed.
fn launch_token_from_user_config(user_config: &str) -> Result<String> {
    let user_config: Value = serde_json::from_str(user_config)
        .context("failed to parse user_config as JSON for requirements.launch_token_hash")?;
    let token = user_config
        .pointer("/dstack/launch_token")
        .context("user_config is missing dstack.launch_token")?
        .as_str()
        .context("user_config dstack.launch_token is not a string")?;
    Ok(token.to_string())
}

pub async fn cmd_sys_setup(args: SetupArgs) -> Result<()> {
    let stage0 = Stage0::load(&args)?;
    set_runtime_event_version(stage0.shared.app_compose.event_log_version)
        .context("failed to configure runtime event version")?;
    let vmm = stage0.host_api();
    let result = do_sys_setup(stage0).await;
    if let Err(err) = &result {
        vmm.notify_q("boot.error", &format!("{err:#}")).await;
    }
    result
}

async fn do_sys_setup(stage0: Stage0<'_>) -> Result<()> {
    verify_app_compose_policy(&stage0.shared).context("Failed to verify app-compose policy")?;
    if stage0.shared.app_compose.secure_time {
        info!("Waiting for the system time to be synchronized");
        cmd! {
            chronyc waitsync 30 0.1 0 5;
        }
        .context("Failed to sync system time")?;
    } else {
        info!("System time will be synchronized by chronyd in background");
    }
    let stage1 = stage0.setup_fs().await?;
    stage1.setup().await
}

/// GPU TEE attestation gate (`requirements.gpu_policy.attest_gpu`, defaults to
/// true).
///
/// Runs before key provisioning so a CVM whose GPU cannot prove it is a
/// genuine, CC-enabled NVIDIA TEE never gets its app keys. An optional
/// application policy is measured and evaluated after `compose-hash`. The GPU
/// "ready" state is only set through NVML from here — nvidia-persistenced
/// deliberately does not set it — so CUDA work cannot be submitted to an
/// unverified GPU either.
mod gpu {
    use super::*;

    const EVENT_VERSION: u32 = 2;
    const POLICY_ENTRYPOINT: &str = "data.policy.nv_match";
    /// Bound Rego evaluation so a runaway application policy cannot hang boot.
    const POLICY_TIMEOUT: Duration = Duration::from_secs(10);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct GpuInventory {
        pub(super) total: u32,
        pub(super) nvidia: u32,
    }

    #[derive(Debug, Serialize)]
    struct GpuAttestationEvent {
        version: u32,
        provider: &'static str,
        devices: u32,
        cc_mode: &'static str,
        devtools: bool,
        evidence_sha256: String,
    }

    pub(super) struct GpuAttestationResult {
        claims: Vec<Value>,
        parsed_claims: Vec<NvidiaGpuClaim>,
        output: Vec<u8>,
        devices: u32,
    }

    impl GpuAttestationResult {
        pub(super) fn claims(&self) -> &[Value] {
            &self.claims
        }

        pub(super) fn event(&self, devtools: bool) -> Result<Vec<u8>> {
            attestation_event(&self.output, self.devices, devtools)
        }

        pub(super) fn verify_claim_policy(
            &self,
            state: &GpuState,
            policy: &GpuPolicy,
        ) -> Result<()> {
            verify_claim_policy(&self.parsed_claims, &state.devices, policy)
        }
    }

    pub(super) struct GpuState {
        nvml: nvml_wrapper::Nvml,
        devices: Vec<GpuDeviceState>,
    }

    impl GpuState {
        pub(super) fn any_devtools(&self) -> bool {
            self.devices.iter().any(|device| device.devtools)
        }

        pub(super) fn set_ready(&self) -> Result<()> {
            set_gpu_ready_state_with_nvml(&self.nvml)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct GpuDeviceState {
        cc_enabled: bool,
        devtools: bool,
    }

    #[derive(Deserialize)]
    struct NvattestOutput {
        result_code: i64,
        claims: Vec<Value>,
    }

    #[derive(Debug, Deserialize)]
    struct NvidiaGpuClaim {
        #[serde(rename = "x-nvidia-device-type")]
        device_type: String,
        eat_nonce: String,
        #[serde(rename = "x-nvidia-gpu-attestation-report-nonce-match")]
        nonce_match: bool,
        measres: String,
        secboot: bool,
        dbgstat: NvidiaGpuDebugStatus,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    enum NvidiaGpuDebugStatus {
        Disabled,
        Enabled,
    }

    struct ValidatedClaims {
        raw: Vec<Value>,
        parsed: Vec<NvidiaGpuClaim>,
    }

    /// Count passed-through display-class GPUs through sysfs so devices which
    /// the NVIDIA driver did not bind cannot be hidden from the gate. Reading
    /// the inventory is fail-closed: a mixed NVIDIA/non-NVIDIA set must not be
    /// represented by an attestation result for only the NVIDIA subset.
    pub(super) fn gpu_inventory() -> Result<GpuInventory> {
        gpu_inventory_at(Path::new("/sys/bus/pci/devices"))
    }

    fn gpu_inventory_at(devices_path: &Path) -> Result<GpuInventory> {
        let entries = fs::read_dir(devices_path).context("failed to enumerate PCI devices")?;
        let mut inventory = GpuInventory {
            total: 0,
            nvidia: 0,
        };
        for entry in entries {
            let device = entry.context("failed to read PCI device entry")?;
            let class_path = device.path().join("class");
            let class = fs::read_to_string(&class_path)
                .with_context(|| format!("failed to read {}", class_path.display()))?;
            if !matches!(class.trim().get(..6), Some("0x0300") | Some("0x0302")) {
                continue;
            }
            inventory.total += 1;
            let vendor_path = device.path().join("vendor");
            let vendor = fs::read_to_string(&vendor_path)
                .with_context(|| format!("failed to read {}", vendor_path.display()))?;
            if vendor.trim() == "0x10de" {
                inventory.nvidia += 1;
            }
        }
        Ok(inventory)
    }

    pub(super) fn nvidia_gpu_count(inventory: GpuInventory) -> Result<u32> {
        if inventory.total != inventory.nvidia {
            bail!(
                "unsupported non-NVIDIA GPU attached: found {} display GPUs, {} NVIDIA",
                inventory.total,
                inventory.nvidia
            );
        }
        Ok(inventory.nvidia)
    }

    fn init_nvml(expected_devices: u32) -> Result<nvml_wrapper::Nvml> {
        let nvml = nvml_wrapper::Nvml::init().context("failed to initialize NVML")?;
        let devices = nvml
            .device_count()
            .context("failed to get NVML GPU count")?;
        if devices != expected_devices {
            bail!("nvml GPU count mismatch: expected {expected_devices}, got {devices}");
        }
        Ok(nvml)
    }

    fn set_gpu_ready_state_with_nvml(nvml: &nvml_wrapper::Nvml) -> Result<()> {
        // nvml-wrapper exposes nvmlSystemSetConfComputeGpusReadyState through
        // Device, but the transition applies to all CC GPUs in the system.
        let first = nvml
            .device_by_index(0)
            .context("failed to get first NVML GPU")?;
        first
            .set_confidential_compute_state(true)
            .context("failed to set GPU ready state")?;
        info!("GPU ready state set");
        Ok(())
    }

    /// Read the CC and DevTools state through NVML for every expected GPU.
    /// NVML exposes these settings as system values through Device methods;
    /// call them for every handle so every expected device must be enumerable.
    pub(super) fn query_gpu_state(expected_devices: u32) -> Result<GpuState> {
        let nvml = init_nvml(expected_devices)?;
        let mut devices = Vec::with_capacity(expected_devices as usize);
        for index in 0..expected_devices {
            let device = nvml
                .device_by_index(index)
                .with_context(|| format!("failed to get NVML GPU at index {index}"))?;
            let cc_enabled = device
                .is_cc_enabled()
                .with_context(|| format!("failed to query CC mode for GPU at index {index}"))?;
            let devtools = device.is_cc_dev_mode_enabled().with_context(|| {
                format!("failed to query DevTools mode for GPU at index {index}")
            })?;
            devices.push(GpuDeviceState {
                cc_enabled,
                devtools,
            });
        }
        Ok(GpuState { nvml, devices })
    }

    /// Set the system-wide GPU ready state without appraisal for the explicit
    /// `gpu_policy.attest_gpu: false` compatibility path.
    pub(super) fn set_gpu_ready_state(expected_devices: u32) -> Result<()> {
        let nvml = init_nvml(expected_devices)?;
        set_gpu_ready_state_with_nvml(&nvml)
    }

    fn validate_attestation_output(
        stdout: &[u8],
        nonce: &str,
        expected_devices: u32,
    ) -> Result<ValidatedClaims> {
        let output: NvattestOutput =
            serde_json::from_slice(stdout).context("failed to parse nvattest JSON output")?;
        if output.result_code != 0 {
            bail!(
                "nvattest JSON result is not successful (result_code={})",
                output.result_code
            );
        }
        if output.claims.len() != expected_devices as usize {
            bail!(
                "gpu attestation count mismatch: expected {expected_devices}, got {}",
                output.claims.len()
            );
        }
        let mut parsed_claims = Vec::with_capacity(output.claims.len());
        for (index, claim) in output.claims.iter().enumerate() {
            let claim: NvidiaGpuClaim = serde_json::from_value(claim.clone())
                .with_context(|| format!("invalid GPU claim at index {index}"))?;
            if claim.device_type != "gpu" {
                bail!("gpu claim at index {index} has an invalid device type");
            }
            if claim.eat_nonce != nonce || !claim.nonce_match {
                bail!("gpu claim at index {index} has an invalid nonce");
            }
            parsed_claims.push(claim);
        }
        Ok(ValidatedClaims {
            raw: output.claims,
            parsed: parsed_claims,
        })
    }

    fn verify_claim_policy(
        claims: &[NvidiaGpuClaim],
        devices: &[GpuDeviceState],
        policy: &GpuPolicy,
    ) -> Result<()> {
        for (index, device) in devices.iter().enumerate() {
            if !device.cc_enabled {
                bail!("gpu at index {index} does not enable confidential compute mode");
            }
            if device.devtools && !policy.allow_devtools {
                bail!("gpu at index {index} enables NVIDIA DevTools mode");
            }
        }
        for (index, claim) in claims.iter().enumerate() {
            if claim.measres != "success" {
                bail!("gpu claim at index {index} has unsuccessful measurements");
            }
            if !policy.allow_insecure_boot && !claim.secboot {
                bail!("gpu claim at index {index} does not assert secure boot");
            }
            if !policy.allow_debug && claim.dbgstat != NvidiaGpuDebugStatus::Disabled {
                bail!("gpu claim at index {index} does not disable debug mode");
            }
        }
        Ok(())
    }

    fn attestation_event(stdout: &[u8], devices: u32, devtools: bool) -> Result<Vec<u8>> {
        let event = GpuAttestationEvent {
            version: EVENT_VERSION,
            provider: "nvidia",
            devices,
            cc_mode: "on",
            devtools,
            evidence_sha256: hex::encode(sha256(stdout)),
        };
        serde_json::to_vec(&event).context("failed to serialize GPU attestation event")
    }

    /// Run local GPU attestation via nvattest with a fresh evidence nonce. If
    /// sys-config selects a collateral proxy, both RIM and OCSP traffic is
    /// routed through it and NVIDIA's Trust Outpost policy accepts cached OCSP
    /// responses whose responder nonce no longer matches. The independent GPU
    /// evidence nonce remains mandatory and is checked below.
    pub(super) async fn attest_gpu(
        expected_devices: u32,
        proxy_url: Option<&str>,
    ) -> Result<GpuAttestationResult> {
        if !nvattest::available() {
            bail!("nvattest is not available in this image");
        }
        // Certificate/OCSP validation needs a sane clock even when
        // secure_time is off; best-effort step chrony before attesting.
        if let Err(err) = cmd!(chronyc makestep) {
            warn!("failed to step system clock: {err:?}");
        }
        let nonce: [u8; nvattest::NONCE_LEN] = rand::thread_rng().gen();
        let (nonce, output) = nvattest::run(&nonce, proxy_url, nvattest::DEFAULT_TIMEOUT).await?;
        // Persist before judging the exit status: a failed appraisal is exactly
        // when the evidence is worth having on disk.
        save_attestation_output(&output.stdout).context("failed to save GPU attestation output")?;
        nvattest::check_status(&output)?;
        let claims = validate_attestation_output(&output.stdout, &nonce, expected_devices)?;
        Ok(GpuAttestationResult {
            claims: claims.raw,
            parsed_claims: claims.parsed,
            output: output.stdout,
            devices: expected_devices,
        })
    }

    pub(super) fn measure_gpu_policy(compose_path: &Path) -> Result<[u8; 32]> {
        let compose_json = fs::read(compose_path)
            .with_context(|| format!("failed to read {}", compose_path.display()))?;
        let digest = gpu_policy_hash(&compose_json).context("failed to hash raw GPU policy")?;
        emit_runtime_event("gpu-policy-hash", &digest)
            .context("failed to emit GPU policy measurement")?;
        Ok(digest)
    }

    pub(super) fn evaluate_rego_policy(policy: &GpuPolicy, claims: &[Value]) -> Result<()> {
        let Some(rego) = policy.rego.as_deref() else {
            return Ok(());
        };
        evaluate_policy(rego, claims).context("failed to apply GPU Rego policy")
    }

    /// Evaluate the app-provided Rego v0 policy using the same input shape as
    /// NVIDIA relying-party policies: the nvattest `claims` JSON array.
    pub(super) fn evaluate_policy(policy: &str, claims: &[Value]) -> Result<()> {
        evaluate_policy_with_timeout(policy, claims, POLICY_TIMEOUT)
    }

    fn evaluate_policy_with_timeout(
        policy: &str,
        claims: &[Value],
        timeout: Duration,
    ) -> Result<()> {
        let mut engine = regorus::Engine::new();
        engine.set_rego_v0(true);
        engine.set_execution_timer_config(regorus::utils::limits::ExecutionTimerConfig {
            limit: timeout,
            check_interval: std::num::NonZeroU32::new(1024).unwrap_or(std::num::NonZeroU32::MIN),
        });
        engine
            .add_policy("gpu-policy.rego".to_string(), policy.to_string())
            .context("failed to load GPU policy")?;
        let input = serde_json::to_string(claims).context("failed to serialize GPU claims")?;
        engine
            .set_input_json(&input)
            .context("failed to set GPU policy input")?;
        if !engine
            .eval_bool_query(POLICY_ENTRYPOINT.to_string(), false)
            .context("failed to evaluate GPU policy")?
        {
            bail!("gpu policy rejected the attestation claims");
        }
        Ok(())
    }

    fn save_attestation_output(stdout: &[u8]) -> Result<()> {
        let output_path = Path::new(GPU_ATTESTATION_OUTPUT);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        safe_write(output_path, stdout)?;
        fs::set_permissions(
            output_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn add_pci_device(root: &Path, name: &str, vendor: &str, class: &str) {
            let device = root.join(name);
            fs::create_dir_all(&device).unwrap();
            fs::write(device.join("vendor"), vendor).unwrap();
            fs::write(device.join("class"), class).unwrap();
        }

        fn nvattest_output(nonce: &str, claims: usize) -> Vec<u8> {
            let claims = (0..claims)
                .map(|_| {
                    serde_json::json!({
                        "x-nvidia-device-type": "gpu",
                        "eat_nonce": nonce,
                        "x-nvidia-gpu-attestation-report-nonce-match": true,
                        "measres": "success",
                        "secboot": true,
                        "dbgstat": "disabled"
                    })
                })
                .collect::<Vec<_>>();
            serde_json::to_vec(&serde_json::json!({
                "result_code": 0,
                "claims": claims,
                "detached_eat": {}
            }))
            .unwrap()
        }

        // Captured with the pinned nvattest SDK on an Ubuntu 22.04 GCP A3 TDX
        // VM with an H100 and the NVIDIA 580 open kernel driver.
        const H100_ATTESTATION_OUTPUT: &[u8] =
            include_bytes!("../tests/fixtures/gpu_attestation_h100.json");

        /// The `AttestGpu` API documents that its output cannot be verified by a
        /// third party, because the local verifier reports a conclusion rather
        /// than the GPU's signed report. That is a claim about NVIDIA's output
        /// format, so pin it: if a future SDK starts signing the detached EAT,
        /// this fails and the API docs need revisiting rather than quietly
        /// becoming wrong.
        #[test]
        fn local_verifier_output_is_unsigned_self_report() {
            let output: Value = serde_json::from_slice(H100_ATTESTATION_OUTPUT).unwrap();
            let eat = &output["detached_eat"];
            let jwt = eat[0][1].as_str().expect("detached EAT carries a JWT");
            let (header_b64, rest) = jwt.split_once('.').unwrap();
            let (_, signature) = rest.split_once('.').unwrap();
            assert!(
                signature.is_empty(),
                "detached EAT is signed; AttestGpu docs claim it is not"
            );

            use base64::Engine as _;
            let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header_b64)
                .unwrap();
            let header: Value = serde_json::from_slice(&header).unwrap();
            assert_eq!(header["alg"], "none");

            // And the signed artifacts really are absent: the claims carry
            // verdicts about the certificate chain, not the chain itself.
            let claim = &output["claims"][0];
            assert_eq!(
                claim["x-nvidia-gpu-attestation-report-signature-verified"],
                true
            );
            assert!(
                claim["x-nvidia-gpu-attestation-report-cert-chain"]
                    .as_object()
                    .expect("cert-chain claim is a verdict object")
                    .keys()
                    .all(|key| key.starts_with("x-nvidia-cert-")),
                "cert-chain claim carries certificates, not just verdicts"
            );
        }

        #[test]
        fn inventory_counts_nvidia_and_non_nvidia_gpus() {
            let root = tempfile::tempdir().unwrap();
            add_pci_device(root.path(), "0000:01:00.0", "0x10de\n", "0x030200\n");
            add_pci_device(root.path(), "0000:02:00.0", "0x1234\n", "0x030000\n");
            add_pci_device(root.path(), "0000:03:00.0", "0x1af4\n", "0x020000\n");
            assert_eq!(
                gpu_inventory_at(root.path()).unwrap(),
                GpuInventory {
                    total: 2,
                    nvidia: 1
                }
            );
        }

        #[test]
        fn gpu_count_rejects_non_nvidia_gpus() {
            let mixed = GpuInventory {
                total: 2,
                nvidia: 1,
            };
            assert!(nvidia_gpu_count(mixed).is_err());

            let nvidia = GpuInventory {
                total: 2,
                nvidia: 2,
            };
            assert_eq!(nvidia_gpu_count(nvidia).unwrap(), 2);
        }

        #[test]
        fn basic_policy_requires_cc_and_rejects_devtools_by_default() {
            let nonce = "44".repeat(32);
            let output = nvattest_output(&nonce, 1);
            let claims = validate_attestation_output(&output, &nonce, 1).unwrap();
            let production = [GpuDeviceState {
                cc_enabled: true,
                devtools: false,
            }];
            verify_claim_policy(&claims.parsed, &production, &GpuPolicy::default()).unwrap();

            let non_cc = [GpuDeviceState {
                cc_enabled: false,
                devtools: false,
            }];
            let err =
                verify_claim_policy(&claims.parsed, &non_cc, &GpuPolicy::default()).unwrap_err();
            assert!(err.to_string().contains("confidential compute mode"));

            let devtools = [GpuDeviceState {
                cc_enabled: true,
                devtools: true,
            }];
            assert!(verify_claim_policy(&claims.parsed, &devtools, &GpuPolicy::default()).is_err());
            verify_claim_policy(
                &claims.parsed,
                &devtools,
                &GpuPolicy {
                    allow_devtools: true,
                    ..Default::default()
                },
            )
            .unwrap();
        }

        #[test]
        fn nvattest_output_requires_every_expected_gpu_and_fresh_nonce() {
            let nonce = "11".repeat(32);
            let valid = nvattest_output(&nonce, 2);
            validate_attestation_output(&valid, &nonce, 2).unwrap();
            assert!(validate_attestation_output(&valid, &nonce, 1).is_err());

            let mut invalid: Value = serde_json::from_slice(&valid).unwrap();
            invalid["claims"][1]["eat_nonce"] = Value::String("stale".to_string());
            assert!(
                validate_attestation_output(&serde_json::to_vec(&invalid).unwrap(), &nonce, 2)
                    .is_err()
            );

            // Basic claim settings are enforced after structural validation.
            let mut extra_claims: Value = serde_json::from_slice(&valid).unwrap();
            extra_claims["claims"][0]["dbgstat"] = Value::String("enabled".to_string());
            validate_attestation_output(&serde_json::to_vec(&extra_claims).unwrap(), &nonce, 2)
                .unwrap();
        }

        #[test]
        fn basic_claim_policy_is_fail_closed_and_honors_opt_ins() {
            let nonce = "33".repeat(32);
            let output = nvattest_output(&nonce, 1);
            let claims = validate_attestation_output(&output, &nonce, 1).unwrap();
            let devices = [GpuDeviceState {
                cc_enabled: true,
                devtools: false,
            }];
            verify_claim_policy(&claims.parsed, &devices, &GpuPolicy::default()).unwrap();

            let with_policy = |name: &str, value: Value, policy: &GpuPolicy| {
                let mut output: Value = serde_json::from_slice(&output).unwrap();
                output["claims"][0][name] = value;
                let output = serde_json::to_vec(&output).unwrap();
                let claims = validate_attestation_output(&output, &nonce, 1).unwrap();
                verify_claim_policy(&claims.parsed, &devices, policy)
            };

            assert!(with_policy("secboot", Value::Bool(false), &GpuPolicy::default()).is_err());
            with_policy(
                "secboot",
                Value::Bool(false),
                &GpuPolicy {
                    allow_insecure_boot: true,
                    ..Default::default()
                },
            )
            .unwrap();

            assert!(with_policy(
                "dbgstat",
                Value::String("enabled".to_string()),
                &GpuPolicy::default(),
            )
            .is_err());
            with_policy(
                "dbgstat",
                Value::String("enabled".to_string()),
                &GpuPolicy {
                    allow_debug: true,
                    ..Default::default()
                },
            )
            .unwrap();

            let mut unknown_debug: Value = serde_json::from_slice(&output).unwrap();
            unknown_debug["claims"][0]["dbgstat"] = Value::String("unknown".to_string());
            assert!(validate_attestation_output(
                &serde_json::to_vec(&unknown_debug).unwrap(),
                &nonce,
                1,
            )
            .is_err());

            assert!(with_policy(
                "measres",
                Value::String("failure".to_string()),
                &GpuPolicy {
                    allow_debug: true,
                    allow_insecure_boot: true,
                    ..Default::default()
                },
            )
            .is_err());

            for required in ["measres", "secboot", "dbgstat"] {
                let mut missing: Value = serde_json::from_slice(&output).unwrap();
                missing["claims"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove(required);
                assert!(validate_attestation_output(
                    &serde_json::to_vec(&missing).unwrap(),
                    &nonce,
                    1,
                )
                .is_err());
            }
        }

        #[test]
        fn real_h100_attestation_fixture_validates_and_drives_rego() {
            let nonce = "11".repeat(32);
            let claims = validate_attestation_output(H100_ATTESTATION_OUTPUT, &nonce, 1).unwrap();
            assert_eq!(claims.raw[0]["hwmodel"], "GH100 A01 GSP BROM");
            assert_eq!(claims.raw[0]["x-nvidia-gpu-claims-version"], "3.0");
            verify_claim_policy(
                &claims.parsed,
                &[GpuDeviceState {
                    cc_enabled: true,
                    devtools: false,
                }],
                &GpuPolicy::default(),
            )
            .unwrap();

            let policy = r#"
                package policy
                default nv_match = false
                nv_match {
                    count(input) == 1
                    input[0].secboot == true
                    input[0].dbgstat == "disabled"
                    input[0].measres == "success"
                }
            "#;
            evaluate_policy(policy, &claims.raw).unwrap();
        }

        #[test]
        fn event_commits_to_complete_nvattest_output() {
            let nonce = "22".repeat(32);
            let output = nvattest_output(&nonce, 1);
            let event: Value =
                serde_json::from_slice(&attestation_event(&output, 1, true).unwrap()).unwrap();
            assert_eq!(event["version"], EVENT_VERSION);
            assert_eq!(event["devices"], 1);
            assert!(event.get("policy").is_none());
            assert_eq!(event["cc_mode"], "on");
            assert_eq!(event["devtools"], true);
            assert_eq!(event["evidence_sha256"], hex::encode(sha256(&output)));
        }

        #[test]
        fn app_policy_receives_claims_array_and_must_return_true() {
            let claims = vec![serde_json::json!({"status": "accepted"})];
            let policy = r#"
                package policy
                default nv_match = false
                nv_match {
                    count(input) == 1
                    input[0].status == "accepted"
                }
            "#;
            evaluate_policy(policy, &claims).unwrap();
            assert!(evaluate_policy(policy, &[]).is_err());

            let rejected = vec![serde_json::json!({"status": "rejected"})];
            assert!(evaluate_policy(policy, &rejected).is_err());
            assert!(evaluate_policy("package policy", &claims).is_err());
            assert!(evaluate_policy("not valid rego", &claims).is_err());

            let allow_no_gpus = GpuPolicy {
                rego: Some(
                    r#"
                        package policy
                        default nv_match = false
                        nv_match { count(input) == 0 }
                    "#
                    .to_string(),
                ),
                ..Default::default()
            };
            evaluate_rego_policy(&allow_no_gpus, &[]).unwrap();

            let require_one_gpu = GpuPolicy {
                rego: Some(policy.to_string()),
                ..Default::default()
            };
            assert!(evaluate_rego_policy(&require_one_gpu, &[]).is_err());
            evaluate_rego_policy(&GpuPolicy::default(), &[]).unwrap();
        }

        #[test]
        fn rego_policy_evaluation_is_time_bounded() {
            let policy = r#"
                package policy
                default nv_match = false
                nv_match {
                    count([x |
                        x := numbers.range(0, 5000)[_]
                        y := numbers.range(0, 5000)[_]
                        x == y
                    ]) > 0
                }
            "#;
            evaluate_policy_with_timeout(policy, &[], Duration::from_millis(50)).unwrap_err();
        }

        #[test]
        fn gpu_policy_measurement_defaults_to_empty_object_and_uses_raw_json() {
            let no_requirements = br#"{}"#;
            let absent = br#"{"requirements": {}}"#;
            let empty_digest = sha256(b"{}");
            assert_eq!(gpu_policy_hash(no_requirements).unwrap(), empty_digest);
            assert_eq!(gpu_policy_hash(absent).unwrap(), empty_digest);

            let empty = br#"{"requirements": {"gpu_policy": {}}}"#;
            assert_eq!(gpu_policy_hash(empty).unwrap(), empty_digest);

            let explicit_default = br#"{"requirements":{"gpu_policy":{"attest_gpu":true}}}"#;
            let explicit_default_digest = gpu_policy_hash(explicit_default).unwrap();
            assert_ne!(explicit_default_digest, empty_digest);

            let reordered = br#"
                {
                    "requirements": {
                        "gpu_policy": {
                            "rego": "package policy",
                            "allow_debug": false
                        }
                    }
                }
            "#;
            let canonical_order =
                br#"{"requirements":{"gpu_policy":{"allow_debug":false,"rego":"package policy"}}}"#;
            assert_eq!(
                gpu_policy_hash(reordered).unwrap(),
                gpu_policy_hash(canonical_order).unwrap()
            );
        }
    }
}

impl Stage0<'_> {
    /// Enforce `requirements.gpu_policy.attest_gpu` (default true): attest an
    /// attached NVIDIA GPU before continuing to key provisioning, or — when
    /// explicitly disabled — set the GPU ready state without verification. The
    /// optional Rego policy is always evaluated; when no attestation is
    /// performed, its claims-array input is empty.
    async fn measure_gpu(&self) -> Result<[u8; 32]> {
        let gpu_policy_hash = gpu::measure_gpu_policy(&self.shared.dir.app_compose_file())?;

        let gpu_policy = self
            .shared
            .app_compose
            .requirements
            .as_ref()
            .map(|requirements| requirements.gpu_policy.clone())
            .unwrap_or_default();

        let inventory = gpu::gpu_inventory()?;
        if !gpu_policy.attest_gpu {
            // Attestation is explicitly disabled, so there are no claims. Rego
            // still runs with an empty input before any GPU is made ready.
            gpu::evaluate_rego_policy(&gpu_policy, &[])?;
            if gpu_policy.rego.is_some() {
                info!("application GPU Rego policy accepted an empty claims array");
            }
            if inventory.nvidia == 0 {
                return Ok(gpu_policy_hash);
            }
            warn!(
                "requirements.gpu_policy.attest_gpu is false; setting GPU ready state without attestation"
            );
            // Best-effort: a GPU with CC mode off has no ready state to set.
            if let Err(err) = gpu::set_gpu_ready_state(inventory.nvidia) {
                warn!("failed to set GPU ready state: {err:?}");
            }
            return Ok(gpu_policy_hash);
        }
        let expected_devices = gpu::nvidia_gpu_count(inventory)?;
        if expected_devices == 0 {
            gpu::evaluate_rego_policy(&gpu_policy, &[])?;
            if gpu_policy.rego.is_some() {
                info!("application GPU Rego policy accepted an empty claims array");
            }
            return Ok(gpu_policy_hash);
        }
        self.vmm.notify_q("boot.progress", "attesting GPU").await;
        info!("verifying GPU TEE attestation");
        let attestation = gpu::attest_gpu(
            expected_devices,
            self.shared
                .sys_config
                .nvidia_attestation_proxy_url
                .as_deref(),
        )
        .await?;

        let gpu_state = gpu::query_gpu_state(expected_devices)?;
        attestation
            .verify_claim_policy(&gpu_state, &gpu_policy)
            .context("failed to apply basic GPU policy")?;
        gpu::evaluate_rego_policy(&gpu_policy, attestation.claims())?;

        info!("application GPU policy accepted the attestation claims and state");
        gpu_state.set_ready()?;
        let devtools = gpu_state.any_devtools();
        let event = attestation.event(devtools)?;
        emit_runtime_event("gpu-attestation", &event)
            .context("failed to emit GPU attestation event")?;
        info!("GPU TEE attestation succeeded");
        Ok(gpu_policy_hash)
    }
}

/// Owns the inputs needed to (re)register this CVM with dstack-gateway.
///
/// Loading is separated from refreshing so a long-running caller (the gateway
/// checker) can pay the parsing cost once and then refresh repeatedly.
pub struct GatewayRefresher {
    shared: HostShared,
    keys: AppKeys,
}

impl GatewayRefresher {
    /// Load the host-shared config and app keys from `work_dir`.
    pub fn load(work_dir: &Path) -> Result<Self> {
        let host_shared_dir = work_dir.join(HOST_SHARED_DIR_NAME);
        let shared = HostShared::load(host_shared_dir.as_path()).with_context(|| {
            format!(
                "Failed to load host-shared dir: {}",
                host_shared_dir.display()
            )
        })?;
        let keys_path = shared.dir.join(APP_KEYS);
        let keys: AppKeys = deserialize_json_file(&keys_path)
            .with_context(|| format!("Failed to load app keys from {}", keys_path.display()))?;
        Ok(Self { shared, keys })
    }

    /// Whether this app opted into dstack-gateway at all.
    pub fn gateway_enabled(&self) -> bool {
        self.shared.app_compose.gateway_enabled()
    }

    /// Validate the parts of the gateway config that can never become valid by
    /// waiting. These are deployment mistakes, not outages, so callers that
    /// retry should give up instead of looping forever.
    pub fn check_config(&self) -> Result<()> {
        if self.keys.gateway_app_id.is_empty() {
            bail!("Missing allowed dstack-gateway app id");
        }
        if self.shared.sys_config.gateway_urls.is_empty()
            && self.shared.sys_config.gateway_clusters.is_empty()
        {
            bail!("Missing gateway urls");
        }
        Ok(())
    }

    /// Register with dstack-gateway and apply the returned WireGuard config.
    pub async fn refresh(&self, force: bool) -> Result<()> {
        GatewayContext::new(&self.shared, &self.keys)
            .setup(force)
            .await
    }
}

pub async fn cmd_gateway_refresh(args: GatewayRefreshArgs) -> Result<()> {
    GatewayRefresher::load(&args.work_dir)?
        .refresh(args.force)
        .await
}

/// Accept only a certificate the KMS issued for its own RPC endpoint.
///
/// The attestation behind this certificate is already verified by the RA-TLS
/// layer, and the KMS identity that matters to the guest is its CA public key,
/// pinned separately by `verify_key_provider_id`. All that is left here is
/// refusing a certificate minted for some other purpose.
fn validate_kms_rpc_cert(cert: Option<CertInfo>) -> Result<()> {
    let Some(cert) = cert else {
        bail!("missing server cert");
    };
    let Some(usage) = cert.special_usage else {
        bail!("missing server cert usage");
    };
    if usage != "kms:rpc" {
        bail!("Invalid server cert usage: {usage}");
    }
    Ok(())
}

struct AppIdValidator {
    allowed_app_id: String,
}

impl AppIdValidator {
    fn validate(&self, cert: Option<CertInfo>) -> Result<()> {
        if self.allowed_app_id == "any" {
            return Ok(());
        }
        let Some(cert) = cert else {
            bail!("Missing TLS certificate info");
        };
        let Some(app_id) = cert.app_id else {
            bail!("Missing app id");
        };
        let app_id = hex::encode(app_id);
        if !self
            .allowed_app_id
            .to_lowercase()
            .contains(&app_id.to_lowercase())
        {
            bail!("Invalid dstack-gateway app id: {app_id}");
        }
        Ok(())
    }
}

struct AppInfo {
    instance_info: InstanceInfo,
    compose_hash: [u8; 32],
    gpu_policy_hash: [u8; 32],
    init_script_hashes: Vec<Vec<u8>>,
}

struct Stage0<'a> {
    args: &'a SetupArgs,
    shared: HostShared,
    vmm: HostApi,
}

struct Stage1<'a> {
    args: &'a SetupArgs,
    vmm: HostApi,
    shared: HostShared,
    keys: AppKeys,
}

fn validate_key_provider_inputs(kind: KeyProviderKind, kms_urls: &[String]) -> Result<()> {
    if kind.is_kms() && kms_urls.is_empty() {
        bail!("No KMS URLs are set");
    }
    Ok(())
}

fn kms_rpc_url(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/prpc") {
        base.to_string()
    } else {
        format!("{base}/prpc")
    }
}

impl<'a> Stage0<'a> {
    fn host_api(&self) -> HostApi {
        HostApi::new(
            self.shared.sys_config.host_api_url.clone(),
            self.shared.sys_config.collateral_urls().pccs,
        )
    }
    fn load(args: &'a SetupArgs) -> Result<Self> {
        let host_shared_copy_dir = args.work_dir.join(HOST_SHARED_DIR_NAME);
        // dstack-attest and the config-id verifier read host-shared files (e.g.
        // the SEV mr_config) from this dir. Export it so they don't fall back to
        // the canonical /dstack/.host-shared, which is only bind-mounted to the
        // work dir after `dstack-util setup` finishes.
        std::env::set_var(
            dstack_types::shared_filenames::HOST_SHARED_DIR_ENV,
            &host_shared_copy_dir,
        );
        let host_shared = HostShared::copy("/tmp/.host-shared".as_ref(), &host_shared_copy_dir)?;
        let host_api = HostApi::new(
            host_shared.sys_config.host_api_url.clone(),
            host_shared.sys_config.collateral_urls().pccs,
        );
        Ok(Self {
            args,
            shared: host_shared,
            vmm: host_api,
        })
    }

    fn app_keys_file(&self) -> PathBuf {
        self.shared.dir.join(APP_KEYS)
    }

    async fn request_app_keys_from_kms_url(&self, kms_url: String) -> Result<AppKeys> {
        info!("Requesting app keys from KMS: {kms_url}");
        let tmp_ca = {
            info!("Getting temp ca cert");
            let client = RaClient::new(kms_url.clone(), true)?;
            let kms_client = dstack_kms_rpc::kms_client::KmsClient::new(client);
            kms_client
                .get_temp_ca_cert()
                .await
                .context("Failed to get temp ca cert")?
        };
        let cert_pair = generate_ra_cert(tmp_ca.temp_ca_cert.clone(), tmp_ca.temp_ca_key.clone())?;
        let attestation_verifier = attestation_verifier(&self.shared.sys_config)?;
        let ra_client = RaClientConfig::builder()
            .tls_no_check(false)
            .tls_built_in_root_certs(false)
            .remote_uri(kms_url.clone())
            .tls_client_cert(cert_pair.cert_pem)
            .tls_client_key(cert_pair.key_pem)
            .tls_ca_cert(tmp_ca.ca_cert.clone())
            .attestation_verifier(attestation_verifier)
            .cert_validator(Box::new(validate_kms_rpc_cert))
            .build()
            .into_client()
            .context("Failed to create client")?;
        let kms_client = dstack_kms_rpc::kms_client::KmsClient::new(ra_client);
        let response = kms_client
            .get_app_key(rpc::GetAppKeyRequest {
                api_version: 1,
                vm_config: self.shared.sys_config.vm_config.clone(),
            })
            .await
            .context("Failed to get app key")?;

        emit_runtime_event("os-image-hash", &response.os_image_hash)
            .context("failed to extend os-image-hash to the launch measurement")?;

        let (_, ca_pem) = x509_parser::pem::parse_x509_pem(tmp_ca.ca_cert.as_bytes())
            .context("Failed to parse ca cert")?;
        let x509 = ca_pem.parse_x509().context("Failed to parse ca cert")?;
        let root_pubkey = x509.public_key().raw.to_vec();

        let keys = AppKeys {
            ca_cert: tmp_ca.ca_cert,
            disk_crypt_key: response.disk_crypt_key,
            env_crypt_key: response.env_crypt_key,
            k256_key: response.k256_key,
            k256_signature: response.k256_signature,
            gateway_app_id: response.gateway_app_id,
            key_provider: KeyProvider::Kms {
                url: kms_url,
                pubkey: root_pubkey,
                tmp_ca_key: tmp_ca.temp_ca_key,
                tmp_ca_cert: tmp_ca.temp_ca_cert,
            },
        };
        Ok(keys)
    }

    async fn request_app_keys_from_kms(&self) -> Result<AppKeys> {
        if self.shared.sys_config.kms_urls.is_empty() {
            bail!("No KMS URLs are set");
        }
        let keys = 'out: {
            let mut error = anyhow!("unknown error");
            for (i, kms_url) in self.shared.sys_config.kms_urls.iter().enumerate() {
                let kms_url = kms_rpc_url(kms_url);
                let response = self.request_app_keys_from_kms_url(kms_url.clone()).await;
                match response {
                    Ok(response) => {
                        break 'out response;
                    }
                    Err(err) => {
                        warn!("Failed to get app keys from KMS {kms_url}: {err:?}");
                        // Record the first error
                        if i == 0 {
                            error = err;
                        }
                    }
                }
            }
            return Err(error).context("Failed to get app keys from KMS");
        };
        Ok(keys)
    }

    fn verify_key_provider_id(&self, provider_id: &[u8]) -> Result<()> {
        let expected_key_provider_id = &self.shared.app_compose.key_provider_id;
        if expected_key_provider_id.is_empty() {
            return Ok(());
        };
        if expected_key_provider_id != provider_id {
            bail!(
                "Unexpected key provider id: {:?}, expected: {:?}",
                hex_fmt::HexFmt(provider_id),
                hex_fmt::HexFmt(expected_key_provider_id)
            );
        }
        Ok(())
    }
    async fn get_keys_from_local_key_provider(&self) -> Result<AppKeys> {
        info!("Getting keys from local key provider");
        let provision = self
            .vmm
            .get_sealing_key()
            .await
            .context("Failed to get sealing key")?;
        // write to fs
        let app_keys = gen_app_keys_from_seed(
            &provision.sk,
            KeyProviderKind::Local,
            Some(provision.mr.to_vec()),
        )
        .context("Failed to generate app keys")?;
        Ok(app_keys)
    }

    fn generate_tpm_app_keys(&self) -> Result<AppKeys> {
        let tpm = TpmContext::detect().context("failed to detect TPM context")?;

        // PCR policy: platform-specific (AWS: sha384 PCR4/7/8/12/14)
        let platform = dstack_types::Platform::detect().context("failed to detect platform")?;
        let pcr_policy =
            tpm::dstack_pcr_policy_for_platform(platform).context("unsupported TPM platform")?;

        // Try to read sealed seed (bound to boot/config/event PCRs)
        if let Some(seed) = tpm
            .unseal::<32>(tpm::SEALED_NV_INDEX, tpm::PRIMARY_KEY_HANDLE, &pcr_policy)
            .context("failed to unseal from TPM")?
        {
            info!(
                "unsealed root key seed from TPM (PCR policy: {})",
                pcr_policy.to_arg()
            );
            return gen_app_keys_from_seed(&seed, KeyProviderKind::Tpm, None)
                .context("failed to generate TPM app keys");
        }

        // No sealed seed exists, generate new one
        info!("no sealed seed found, generating new seed...");
        let seed: [u8; 32] = tpm.get_random().context("TPM RNG unavailable")?;
        // Seal the new seed under the platform PCR policy
        tpm.seal(
            &seed,
            tpm::SEALED_NV_INDEX,
            tpm::PRIMARY_KEY_HANDLE,
            &pcr_policy,
        )
        .context("failed to seal seed to TPM")?;

        gen_app_keys_from_seed(&seed, KeyProviderKind::Tpm, None)
            .context("failed to generate TPM app keys")
    }

    async fn request_app_keys(&self) -> Result<AppKeys> {
        let key_provider = self.shared.app_compose.key_provider();
        validate_key_provider_inputs(key_provider, &self.shared.sys_config.kms_urls)?;
        match key_provider {
            KeyProviderKind::Kms => self.request_app_keys_from_kms().await,
            KeyProviderKind::Local => self.get_keys_from_local_key_provider().await,
            KeyProviderKind::None => {
                info!("No key provider is enabled, generating temporary app keys");
                let seed: [u8; 32] = rand::thread_rng().gen();
                gen_app_keys_from_seed(&seed, KeyProviderKind::None, None)
                    .context("Failed to generate app keys")
            }
            KeyProviderKind::Tpm => {
                info!("Generating app keys from TPM");
                self.generate_tpm_app_keys()
            }
        }
    }

    async fn setup_swap(&self, swap_size: u64, opts: &DstackOptions) -> Result<()> {
        match opts.storage_fs {
            FsType::Zfs => self.setup_swap_zvol(swap_size).await,
            FsType::Ext4 => self.setup_swapfile(swap_size).await,
        }
    }

    async fn setup_swapfile(&self, swap_size: u64) -> Result<()> {
        let swapfile = self.args.mount_point.join("swapfile");
        if swapfile.exists() {
            fs::remove_file(&swapfile).context("Failed to remove swapfile")?;
            info!("Removed existing swapfile");
        }
        if swap_size == 0 {
            return Ok(());
        }
        let swapfile = swapfile.display().to_string();
        info!("Creating swapfile at {swapfile} (size {swap_size} bytes)");
        let size_str = swap_size.to_string();
        cmd! {
            fallocate -l $size_str $swapfile;
            chmod 600 $swapfile;
            mkswap $swapfile;
            swapon $swapfile;
            swapon --show;
        }
        .context("Failed to enable swap on swapfile")?;
        Ok(())
    }

    async fn setup_swap_zvol(&self, swap_size: u64) -> Result<()> {
        let swapvol_path = "dstack/swap";
        let swapvol_device_path = format!("/dev/zvol/{swapvol_path}");

        if Path::new(&swapvol_device_path).exists() {
            cmd! {
                zfs set volmode=none $swapvol_path;
                zfs destroy $swapvol_path;
            }
            .context("Failed to destroy swap zvol")?;
        }

        if swap_size == 0 {
            return Ok(());
        }

        info!("Creating swap zvol at {swapvol_device_path} (size {swap_size} bytes)");

        let size_str = swap_size.to_string();
        cmd! {
            zfs create -V $size_str
                -o compression=zle
                -o logbias=throughput
                -o sync=always
                -o primarycache=metadata
                -o com.sun:auto-snapshot=false
                $swapvol_path
        }
        .with_context(|| format!("Failed to create swap zvol {swapvol_path}"))?;

        let mut count = 0u32;
        while !Path::new(&swapvol_device_path).exists() && count < 10 {
            std::thread::sleep(Duration::from_secs(1));
            count += 1;
        }
        if !Path::new(&swapvol_device_path).exists() {
            bail!("Device {swapvol_device_path} did not appear after 10 seconds");
        }

        cmd! {
            mkswap $swapvol_device_path;
            swapon $swapvol_device_path;
            swapon --show;
        }
        .context("Failed to enable swap on zvol")?;

        Ok(())
    }

    fn is_disk_initialized(&self, opts: &DstackOptions) -> bool {
        let device = &self.args.device;

        // For encrypted storage, just check if LUKS header exists
        // The filesystem check happens after the LUKS device is opened
        let has_luks = if opts.storage_encrypted {
            let result = cmd!(cryptsetup isLuks $device).is_ok();
            if result {
                info!("LUKS header detected on {}", device.display());
            }
            result
        } else {
            false
        };

        // Check if filesystem exists
        let has_fs = match opts.storage_fs {
            FsType::Zfs => {
                // Check if zpool exists by trying to import it in readonly mode
                if cmd!(zpool import -N -o readonly=on dstack).is_ok() {
                    cmd!(zpool export dstack).ok();
                    info!("ZFS pool 'dstack' detected");
                    true
                } else {
                    false
                }
            }
            FsType::Ext4 if !opts.storage_encrypted => {
                // For unencrypted ext4, check the device directly
                if cmd!(blkid -s TYPE -o value $device)
                    .map(|out| out.trim() == "ext4")
                    .unwrap_or(false)
                {
                    info!("ext4 filesystem detected on {}", device.display());
                    true
                } else {
                    false
                }
            }
            FsType::Ext4 => {
                // For encrypted ext4, we can only check after LUKS is opened
                // So we rely on LUKS header presence as indicator
                has_luks
            }
        };

        // For encrypted filesystems, we can only detect the filesystem after LUKS is opened
        // So we rely on LUKS header presence as the indicator for both ext4 and ZFS
        let initialized = if opts.storage_encrypted {
            has_luks
        } else {
            has_fs
        };

        if !initialized {
            info!("No existing filesystem detected on {}", device.display());
        }
        initialized
    }

    async fn mount_data_disk(&self, disk_crypt_key: &str, opts: &DstackOptions) -> Result<()> {
        let name = "dstack_data_disk";
        let mount_point = &self.args.mount_point;

        // Determine the device to use based on encryption settings
        let fs_dev = if opts.storage_encrypted {
            format!("/dev/mapper/{name}")
        } else {
            self.args.device.to_string_lossy().to_string()
        };

        cmd!(mkdir -p $mount_point).context("Failed to create mount point")?;

        let disk_initialized = self.is_disk_initialized(opts);

        if !disk_initialized {
            self.vmm
                .notify_q("boot.progress", "initializing data disk")
                .await;

            if opts.storage_encrypted {
                info!("Setting up disk encryption");
                self.luks_setup(disk_crypt_key, name)?;
            } else {
                info!("Skipping disk encryption as requested by kernel cmdline");
            }

            match opts.storage_fs {
                FsType::Zfs => {
                    info!("Creating ZFS filesystem");
                    cmd! {
                        zpool create -o autoexpand=on -m none dstack $fs_dev;
                        zfs create -o mountpoint=$mount_point -o atime=off -o checksum=blake3 dstack/data;
                    }
                    .context("Failed to create zpool")?;
                }
                FsType::Ext4 => {
                    info!("Creating ext4 filesystem");
                    cmd! {
                        mkfs.ext4 -F $fs_dev;
                        mount $fs_dev $mount_point;
                    }
                    .context("Failed to create ext4 filesystem")?;
                }
            }
        } else {
            self.vmm
                .notify_q("boot.progress", "mounting data disk")
                .await;

            if opts.storage_encrypted {
                info!("Mounting encrypted data disk");
                self.open_encrypted_volume(disk_crypt_key, name)?;
            } else {
                info!("Mounting unencrypted data disk");
            }

            match opts.storage_fs {
                FsType::Zfs => {
                    cmd! {
                        zpool import dstack;
                        zpool status dstack;
                        zpool online -e dstack $fs_dev; // triggers autoexpand
                    }
                    .context("Failed to import zpool")?;
                    if cmd!(mountpoint -q $mount_point).is_err() {
                        cmd!(zfs mount dstack/data).context("Failed to mount zpool")?;
                    }
                }
                FsType::Ext4 => {
                    Self::mount_e2fs(&fs_dev, mount_point)
                        .context("Failed to mount ext4 filesystem")?;
                }
            }
        }
        Ok(())
    }

    fn mount_e2fs(dev: &impl AsRef<Path>, mount_point: &impl AsRef<Path>) -> Result<()> {
        let dev = dev.as_ref();
        let mount_point = mount_point.as_ref();
        info!("Checking filesystem");

        let e2fsck_status = Command::new("e2fsck")
            .arg("-f")
            .arg("-p")
            .arg(dev)
            .status()
            .with_context(|| format!("Failed to run e2fsck on {}", dev.display()))?;

        match e2fsck_status.code() {
            Some(0 | 1) => {}
            Some(code) => {
                bail!(
                    "e2fsck exited with status {code} while checking {}",
                    dev.display()
                );
            }
            None => {
                bail!(
                    "e2fsck terminated by signal while checking {}",
                    dev.display()
                );
            }
        }

        cmd! {
            info "Trying to resize filesystem if needed";
            resize2fs $dev;
            info "Mounting filesystem";
            mount $dev $mount_point;
        }
        .context("Failed to prepare ext4 filesystem")?;
        Ok(())
    }

    fn luks_setup(&self, disk_crypt_key: &str, name: &str) -> Result<()> {
        let root_hd = &self.args.device;
        let sector_offset = PAYLOAD_OFFSET / 512;
        info!("Formatting encrypted disk");
        let sector_offset = sector_offset.to_string();
        let mut child = Command::new("cryptsetup")
            .args([
                "luksFormat",
                "--type",
                "luks2",
                "--offset",
                &sector_offset,
                "--cipher",
                "aes-xts-plain64",
                "--pbkdf",
                "pbkdf2",
                "-d-",
            ])
            .arg(root_hd)
            .arg(name)
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to start cryptsetup luksFormat")?;
        child
            .stdin
            .take()
            .context("cryptsetup stdin is unavailable")?
            .write_all(disk_crypt_key.as_bytes())
            .context("Failed to send key to cryptsetup luksFormat")?;
        if !child
            .wait()
            .context("Failed to wait for cryptsetup luksFormat")?
            .success()
        {
            bail!("Failed to setup luks volume");
        }
        self.open_encrypted_volume(disk_crypt_key, name)
    }

    fn open_encrypted_volume(&self, disk_crypt_key: &str, name: &str) -> Result<()> {
        let root_hd = &self.args.device;
        let disk_crypt_key = disk_crypt_key.trim();
        // Create a private tmpfs mount to ensure the header stays in-memory.
        let tmp_hdr_dir = "/tmp/dstack-luks-header";
        let in_mem_hdr = format!("{tmp_hdr_dir}/luks-header");
        defer! {
            // Ensure cleanup of header file and tmpfs mount.
            cmd! {
                info "Cleaning up in-memory LUKS header";
                rm -f $in_mem_hdr;
                umount $tmp_hdr_dir;
                rmdir $tmp_hdr_dir;
            }.ok();
        }
        cmd! {
            info "Mounting tmpfs for in-memory LUKS header";
            mkdir -p $tmp_hdr_dir;
            mount -t tmpfs -o size=64M,mode=0700,nosuid,nodev,noexec tmpfs $tmp_hdr_dir;
            info "Loading the LUKS2 header";
            cryptsetup luksHeaderBackup --header-backup-file=$in_mem_hdr $root_hd;
        }
        .context("Failed to load LUKS2 header")?;

        let hdr_file = fs::File::open(&in_mem_hdr).context("Failed to open LUKS2 header")?;
        validate_luks2_headers(hdr_file).context("Failed to validate LUKS2 header")?;

        info!("Opening the device");
        let mut child = Command::new("cryptsetup")
            .args(["luksOpen", "--type", "luks2", "--header"])
            .arg(&in_mem_hdr)
            .arg("-d-")
            .arg(root_hd)
            .arg(name)
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to start cryptsetup luksOpen")?;
        child
            .stdin
            .take()
            .context("cryptsetup stdin is unavailable")?
            .write_all(disk_crypt_key.as_bytes())
            .context("Failed to send key to cryptsetup luksOpen")?;
        if !child
            .wait()
            .context("Failed to wait for cryptsetup luksOpen")?
            .success()
        {
            bail!("Failed to open encrypted data disk");
        }

        // Wait for device mapper to create the device
        let dm_path = format!("/dev/mapper/{name}");
        for i in 0..10 {
            if std::path::Path::new(&dm_path).exists() {
                info!("Device mapper {} is ready", dm_path);
                break;
            }
            if i == 9 {
                bail!("Timed out waiting for device mapper {}", dm_path);
            }
            info!("Waiting for device mapper {}...", dm_path);
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Ok(())
    }

    async fn measure_app_info(&self) -> Result<AppInfo> {
        let compose_hash = sha256_file(self.shared.dir.app_compose_file())?;
        let truncated_compose_hash = truncate(&compose_hash, 20);
        let key_provider = self.shared.app_compose.key_provider();
        let mut instance_info = self.shared.instance_info.clone();
        let is_snp = detect_tee_variant()
            .map(|mode| mode == TeeVariant::DstackAmdSevSnp)
            .unwrap_or(false);

        if instance_info.app_id.is_empty() {
            instance_info.app_id = truncated_compose_hash.to_vec();
        }
        if instance_info.app_id.len() != 20 {
            bail!(
                "Invalid app id length: expected 20 bytes, got {}",
                instance_info.app_id.len()
            );
        }

        let disk_reusable = !key_provider.is_none();
        if ((!disk_reusable) && !is_snp) || instance_info.instance_id_seed.is_empty() {
            instance_info.instance_id_seed = {
                let mut rand_id = vec![0u8; 20];
                getrandom::fill(&mut rand_id)?;
                rand_id
            };
        }
        let instance_id = if self.shared.app_compose.no_instance_id {
            vec![]
        } else {
            let mut id_path = instance_info.instance_id_seed.clone();
            id_path.extend_from_slice(&instance_info.app_id);
            if !is_snp {
                if let Some(binding) = platform_instance_binding()? {
                    info!("mixing platform per-instance binding into instance_id");
                    id_path.extend_from_slice(&binding);
                }
            }
            sha256(&id_path)[..20].to_vec()
        };
        instance_info.instance_id = instance_id.clone();
        // app_id is the deploy-time instance_info.app_id (which defaults to the
        // truncated compose hash when unset, see above). Previously the non-KMS
        // path forced the compose-derived value; now a deployment may pin an
        // explicit app_id even without a KMS. The app_id is measured into the
        // platform launch register, so a verifier sees exactly this value. With
        // no KMS to bind it, the relying party MUST gate the compose_hash
        // (which launcher build) separately from the app_id (which app).

        emit_runtime_event("system-preparing", &[])?;
        emit_runtime_event("app-id", &instance_info.app_id)?;
        emit_runtime_event("compose-hash", &compose_hash)?;
        let init_script_hashes: Vec<Vec<u8>> = self
            .shared
            .app_compose
            .init_script
            .iter()
            .map(|script| sha256(script.as_bytes()).to_vec())
            .collect();
        for script_hash in &init_script_hashes {
            emit_runtime_event("init-script-hash", script_hash)?;
        }
        let gpu_policy_hash = self
            .measure_gpu()
            .await
            .context("failed to verify GPU TEE attestation")?;

        emit_runtime_event("instance-id", &instance_id)?;
        emit_runtime_event("boot-mr-done", &[])?;

        // AWS: commit the measured app identity into PCR8 (mr_config analogue).
        // The config id is computed from measured reality (MrConfig V2), so
        // there is no host-supplied claim to cross-check later. key_provider_id
        // is the deploy-time pin from app-compose (empty = not pinned); the
        // actual provider id is enforced against the pin in
        // verify_key_provider_id.
        let aws_config_id = dstack_types::mr_config::MrConfig::V2 {
            compose_hash: &compose_hash,
            app_id: instance_info
                .app_id
                .as_slice()
                .try_into()
                .ok()
                .context("invalid app id")?,
            key_provider,
            key_provider_id: &self.shared.app_compose.key_provider_id,
        }
        .to_mr_config_id();
        dstack_attest::measure_aws_config_pcr(&aws_config_id)
            .context("failed to measure AWS config into PCR8")?;

        Ok(AppInfo {
            instance_info,
            compose_hash,
            gpu_policy_hash,
            init_script_hashes,
        })
    }

    fn verify_app(&self, app_info: &AppInfo, keys: &AppKeys) -> Result<()> {
        config_id_verifier::verify_mr_config_id(
            &app_info.compose_hash,
            &app_info.gpu_policy_hash,
            &app_info.init_script_hashes,
            &app_info
                .instance_info
                .app_id
                .as_slice()
                .try_into()
                .ok()
                .context("Invalid app id")?,
            &app_info.instance_info.instance_id,
            keys.key_provider.kind(),
            keys.key_provider.id(),
        )?;
        self.verify_key_provider_id(keys.key_provider.id())?;
        // TPM uses an empty id: the instance app-root pubkey is not a stable
        // provider identity and must not enter the launch measurement chain.
        let kp_info = match &keys.key_provider {
            KeyProvider::None { .. } => KeyProviderInfo::new("none".into(), "".into()),
            KeyProvider::Local { .. } => {
                KeyProviderInfo::new("local-sgx".into(), hex::encode(keys.key_provider.id()))
            }
            KeyProvider::Tpm { .. } => KeyProviderInfo::new("tpm".into(), "".into()),
            KeyProvider::Kms { .. } => {
                KeyProviderInfo::new("kms".into(), hex::encode(keys.key_provider.id()))
            }
        };
        emit_key_provider_info(&kp_info)?;
        Ok(())
    }

    async fn setup_fs(self) -> Result<Stage1<'a>> {
        let app_info = self
            .measure_app_info()
            .await
            .context("Failed to measure app info")?;
        if self.shared.app_compose.key_provider().is_kms() {
            cmd_show_mrs()?;
        }
        self.vmm
            .notify_q("boot.progress", "requesting app keys")
            .await;
        let app_keys = self
            .request_app_keys()
            .await
            .context("Failed to request app keys")?;
        if app_keys.disk_crypt_key.is_empty() {
            bail!("Failed to get valid key phrase from KMS");
        }

        self.verify_app(&app_info, &app_keys)
            .context("Failed to verify app")?;

        // Save app keys
        let keys_json = serde_json::to_string(&app_keys).context("Failed to serialize app keys")?;
        fs::write(self.app_keys_file(), keys_json).context("Failed to write app keys")?;

        // Parse kernel command line options
        let opts = parse_dstack_options(&self.shared).context("Failed to parse kernel cmdline")?;
        emit_runtime_event("storage-fs", opts.storage_fs.to_string().as_bytes())?;
        info!(
            "Filesystem options: encryption={}, filesystem={:?}",
            opts.storage_encrypted, opts.storage_fs
        );

        self.mount_data_disk(&hex::encode(&app_keys.disk_crypt_key), &opts)
            .await?;
        self.setup_swap(self.shared.app_compose.swap_size, &opts)
            .await?;
        self.vmm
            .notify_q(
                "instance.info",
                &serde_json::to_string(&app_info.instance_info)?,
            )
            .await;
        emit_runtime_event("system-ready", &[])?;
        self.vmm.notify_q("boot.progress", "data disk ready").await;

        if !self.shared.app_compose.key_provider().is_kms() {
            cmd_show_mrs()?;
        }
        Ok(Stage1 {
            args: self.args,
            shared: self.shared,
            vmm: self.vmm,
            keys: app_keys,
        })
    }
}

impl Stage1<'_> {
    fn decrypt_env_vars(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        allowed: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, String>> {
        let vars = if !key.is_empty() && !ciphertext.is_empty() {
            info!("Processing encrypted env");
            let env_crypt_key: [u8; 32] = key
                .try_into()
                .ok()
                .context("Invalid env crypt key length")?;
            let decrypted_json =
                dh_decrypt(env_crypt_key, ciphertext).context("Failed to decrypt env file")?;
            crate::parse_env_file::parse_env(&decrypted_json, allowed)?
        } else {
            info!("No encrypted env, using default");
            Default::default()
        };
        Ok(vars)
    }

    fn write_env_file(&self, env_vars: &BTreeMap<String, String>) -> Result<()> {
        info!("Writing env");
        fs::write(
            self.shared.dir.join(DECRYPTED_ENV),
            crate::parse_env_file::convert_env_to_str(env_vars),
        )
        .context("Failed to write decrypted env file")?;
        let env_json = fs::File::create(self.shared.dir.join(DECRYPTED_ENV_JSON))
            .context("Failed to create env file")?;
        serde_json::to_writer(env_json, &env_vars).context("Failed to write decrypted env file")?;
        Ok(())
    }

    fn unseal_env_vars(&self) -> Result<BTreeMap<String, String>> {
        let allowed_envs: BTreeSet<String> = self
            .shared
            .app_compose
            .allowed_envs
            .iter()
            .cloned()
            .collect();
        // Decrypt env file
        let decrypted_env = self.decrypt_env_vars(
            &self.keys.env_crypt_key,
            &self.shared.encrypted_env,
            &allowed_envs,
        )?;
        self.write_env_file(&decrypted_env)?;
        Ok(decrypted_env)
    }

    async fn setup(&self) -> Result<()> {
        let _envs = self.unseal_env_vars()?;
        self.link_files()?;
        self.setup_socket_dir()?;
        self.setup_guest_agent_config()?;
        self.vmm
            .notify_q("boot.progress", "setting up dstack-gateway")
            .await;
        if let Err(error) = GatewayContext::new(&self.shared, &self.keys)
            .setup(true)
            .await
        {
            warn!(
                "dstack-gateway registration is unavailable during boot; continuing without a route: {error:#}"
            );
            // Boot no longer fails here, so a guest log line would be the only
            // trace of it: the VM would report a clean boot while having no
            // ingress at all. Report it to the host so the degraded state is
            // visible from the VMM. The gateway checker clears this once it
            // manages to register.
            self.vmm
                .notify_q(
                    "boot.error",
                    &format!(
                        "dstack-gateway registration failed, the app has no ingress route: {error:#}"
                    ),
                )
                .await;
        }
        self.vmm
            .notify_q("boot.progress", "setting up docker")
            .await;
        self.setup_docker_registry()?;
        Ok(())
    }

    fn link_files(&self) -> Result<()> {
        let work_dir = &self.args.work_dir;
        cmd! {
            cd $work_dir;
            ln -sf ${HOST_SHARED_DIR_NAME}/${APP_COMPOSE};
            ln -sf ${HOST_SHARED_DIR_NAME}/${USER_CONFIG} user_config;
        }?;
        Ok(())
    }

    /// Setup socket directory for dstack-guest-agent.
    fn setup_socket_dir(&self) -> Result<()> {
        info!("Setting up socket directory");
        fs::create_dir_all("/var/run/dstack").context("Failed to create socket directory")?;
        Ok(())
    }

    fn setup_guest_agent_config(&self) -> Result<()> {
        info!("Setting up guest agent config");
        let data_disks = ["/".as_ref() as &Path, self.args.mount_point.as_ref()];
        let config = serde_json::json!({
            "default": {
                "core": {
                    "data_disks": data_disks,
                }
            }
        });
        // /dstack/agent.json
        let agent_config = self.args.work_dir.join("agent.json");
        fs::write(agent_config, serde_json::to_string_pretty(&config)?)?;
        Ok(())
    }

    fn setup_docker_registry(&self) -> Result<()> {
        info!("Setting up docker registry");
        let registry_url = self
            .shared
            .sys_config
            .docker_registry
            .as_deref()
            .unwrap_or_default();
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
}

macro_rules! const_pad {
    ($s:expr, $len:expr) => {
        const {
            assert!($s.len() <= $len, "The s is too long");
            let mut padded: [u8; $len] = [0; $len];
            let mut i = 0;
            while i < $s.len() {
                padded[i] = $s[i];
                i += 1;
            }
            padded
        }
    };
}

const PAYLOAD_OFFSET: u64 = 16777216;

fn validate_luks2_headers(mut reader: impl std::io::Read) -> Result<()> {
    validate_single_luks2_header(&mut reader, 0)?;
    validate_single_luks2_header(&mut reader, 1)?;
    Ok(())
}

fn validate_single_luks2_header(mut reader: impl std::io::Read, hdr_ind: u64) -> Result<()> {
    let mut hdr_data = vec![0u8; 4096];
    reader
        .read_exact(&mut hdr_data)
        .context("Failed to read LUKS header")?;
    let header =
        LuksHeader::read_from(&mut &hdr_data[..]).context("Failed to decode LUKS header")?;
    let LuksHeader {
        magic,
        version,
        hdr_size,
        seqid: _,
        label,
        csum_alg,
        salt: _,
        uuid: _,
        subsystem,
        hdr_offset,
        csum: _,
        ..
    } = header;

    let expected_magic = match hdr_ind {
        0 => [76, 85, 75, 83, 186, 190],
        1 => [83, 75, 85, 76, 186, 190],
        _ => bail!("Invalid LUKS header index: {hdr_ind}"),
    };
    if magic != expected_magic {
        bail!("Invalid LUKS magic: {magic:?}");
    }
    if version != 2 {
        bail!("Invalid LUKS version: {version}");
    }
    if label != [0; 48] {
        bail!("Invalid LUKS label: {:?}", label);
    }
    if csum_alg != const_pad!(b"sha256", 32) {
        bail!("Invalid LUKS checksum algorithm");
    }
    if subsystem != [0; 48] {
        bail!("Invalid LUKS subsystem");
    }
    if hdr_offset != hdr_ind * hdr_size {
        bail!("Invalid LUKS header offset: {hdr_offset}");
    }
    if !(4096..=1024 * 1024 * 16).contains(&hdr_size) {
        bail!("Invalid LUKS header size: {hdr_size}");
    }

    // Check JSON
    let json_size = hdr_size - 4096;
    let mut jsn_data = vec![0u8; json_size as usize];
    reader
        .read_exact(&mut jsn_data)
        .context("Failed to read LUKS JSON")?;
    let json_end = jsn_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(jsn_data.len());
    jsn_data.truncate(json_end);

    let json = LuksJson::read_from(&mut &jsn_data[..]).context("Failed to decode LUKS JSON")?;
    let LuksJson {
        keyslots,
        tokens,
        segments,
        digests,
        config:
            LuksConfig {
                json_size: _,
                keyslots_size: _,
                flags,
                requirements,
            },
    } = json;

    if keyslots.len() != 1 {
        bail!("Invalid LUKS keyslots");
    }
    if !tokens.is_empty() {
        bail!("Invalid LUKS tokens");
    }
    if segments.len() != 1 {
        bail!("Invalid LUKS segments");
    }
    if digests.len() != 1 {
        bail!("Invalid LUKS digests");
    }
    if flags.is_some() {
        bail!("Invalid LUKS flags");
    }
    if requirements.is_some() {
        bail!("Invalid LUKS requirements");
    }

    {
        let first_keyslot = keyslots.get(&0).context("no LUKS keyslot")?;
        let LuksKeyslot::luks2 {
            key_size,
            area,
            kdf,
            af,
            priority,
        } = first_keyslot;
        if area.encryption() != "aes-xts-plain64" {
            bail!("Invalid LUKS keyslot encryption: {}", area.encryption());
        }
        // Pin where the encrypted key material is read from. The binary area
        // must sit between the two header copies and the encrypted payload;
        // otherwise a host with raw disk access could redirect it elsewhere.
        if area.offset() < 2 * hdr_size || area.offset() + area.size() > PAYLOAD_OFFSET {
            bail!(
                "Invalid LUKS keyslot area: offset={} size={}",
                area.offset(),
                area.size()
            );
        }
        if *key_size != 64 {
            bail!("Invalid LUKS keyslot key size: {key_size}");
        }
        if area.key_size() != 64 {
            bail!("Invalid LUKS keyslot key size: {}", area.key_size());
        }
        {
            let LuksKdf::pbkdf2 {
                hash,
                iterations: _,
                // Salts are left unchecked on purpose: the passphrase is
                // high-entropy and KMS-derived, so an attacker-chosen salt
                // buys nothing without it (see security report #552).
                salt: _,
            } = kdf
            else {
                bail!("Invalid LUKS keyslot KDF");
            };
            if hash != "sha256" {
                bail!("Invalid LUKS keyslot hash: {hash}");
            }
        }
        {
            let LuksAf::luks1 { hash, stripes } = af;
            if hash != "sha256" {
                bail!("Invalid LUKS keyslot hash: {hash}");
            }
            if *stripes != 4000 {
                bail!("Invalid LUKS keyslot stripes: {stripes}");
            }
        }
        if priority.is_some() {
            bail!("Invalid LUKS keyslot priority");
        }
    }

    {
        let first_segment = segments.get(&0).context("no LUKS segment")?;
        let LuksSegment::crypt {
            offset,
            size,
            iv_tweak,
            encryption,
            sector_size,
            integrity,
            flags,
        } = first_segment;
        if *offset != PAYLOAD_OFFSET {
            bail!("Invalid LUKS segment offset");
        }
        if *size != LuksSegmentSize::dynamic {
            bail!("Invalid LUKS segment size");
        }
        if *iv_tweak != 0 {
            bail!("Invalid LUKS segment IV tweak");
        }
        if encryption != "aes-xts-plain64" {
            bail!("Invalid LUKS segment encryption");
        }
        if *sector_size != 512 {
            bail!("Invalid LUKS segment sector size");
        }
        if integrity.is_some() {
            bail!("Invalid LUKS segment integrity");
        }
        if flags.is_some() {
            bail!("Invalid LUKS segment flags");
        }
    }
    {
        let first_digest = digests.get(&0).context("no LUKS digest")?;
        let LuksDigest::pbkdf2 {
            keyslots,
            segments,
            hash,
            digest: _,
            iterations: _,
            salt: _,
        } = first_digest;
        if hash != "sha256" {
            bail!("Invalid LUKS digest hash: {hash}");
        }
        if keyslots != &[0] {
            bail!("Invalid LUKS digest keyslots: {keyslots:?}");
        }
        if segments != &[0] {
            bail!("Invalid LUKS digest segments: {segments:?}");
        }
    }
    Ok(())
}

#[test]
fn test_validate_luks2_header() {
    let header_data = include_bytes!("../tests/fixtures/luks_header_good").to_vec();
    validate_luks2_headers(&mut &header_data[..]).expect("Failed to validate LUKS2 header");
    let header_data = include_bytes!("../tests/fixtures/luks_header_cipher_null").to_vec();
    let error = validate_luks2_headers(&mut &header_data[..]).unwrap_err();
    assert!(error
        .to_string()
        .contains("Invalid LUKS keyslot encryption"));
}

#[test]
fn test_validate_luks2_header_rejects_out_of_range_keyslot_area() {
    // Redirect the keyslot binary area below the header region. Same length
    // so the surrounding header stays intact; "00768" parses to 768, which is
    // inside the header copies (< 2 * hdr_size) rather than the metadata gap.
    let mut header = include_bytes!("../tests/fixtures/luks_header_good").to_vec();
    let needle = br#""offset":"32768""#;
    let replacement = br#""offset":"00768""#;
    let mut patched = 0;
    let mut i = 0;
    while i + needle.len() <= header.len() {
        if &header[i..i + needle.len()] == needle {
            header[i..i + needle.len()].copy_from_slice(replacement);
            patched += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    assert_eq!(patched, 2, "expected to patch both header copies");
    let error = validate_luks2_headers(&mut &header[..]).unwrap_err();
    assert!(error.to_string().contains("Invalid LUKS keyslot area"));
}

#[cfg(test)]
fn test_app_compose(manifest_version: serde_json::Value, platforms: Option<&[&str]>) -> AppCompose {
    let mut value = serde_json::json!({
        "manifest_version": manifest_version,
        "name": "test",
        "runner": "docker-compose"
    });
    if platforms.is_some() {
        value["requirements"] = serde_json::json!({});
    }
    if let Some(platforms) = platforms {
        value["requirements"]["platforms"] = serde_json::json!(platforms);
    }
    serde_json::from_value(value).unwrap()
}

/// The single hop between `requirements.health_check` and
/// `RegisterCvmRequest.health_check`. Nothing else connects the app's manifest
/// to the gateway's behaviour, so if this is wrong the feature is inert
/// fleet-wide and nothing else fails.
#[test]
fn health_check_opt_in_reaches_registration() {
    let opted_in =
        compose_with_health_check("docker-compose", serde_json::json!({"health_check": true}));
    assert!(health_check_requested(&opted_in));

    let opted_out =
        compose_with_health_check("docker-compose", serde_json::json!({"health_check": false}));
    assert!(!health_check_requested(&opted_out));
}

/// An app that says nothing must register as "do not poll me", not as an
/// opt-in by omission.
#[test]
fn an_app_that_says_nothing_does_not_ask_to_be_polled() {
    let no_requirements = test_app_compose(serde_json::json!("3"), None);
    assert!(!health_check_requested(&no_requirements));

    // Requirements present, but carrying something other than health_check.
    let other_requirements = test_app_compose(serde_json::json!("3"), Some(&["dstack-tdx"]));
    assert!(!health_check_requested(&other_requirements));
}

/// An app that opts into health gating, with `overrides` merged over the
/// `requirements` object so a case can vary one field without restating it.
///
/// The compose file deliberately declares no `healthcheck:`. Whether the
/// containers can be judged is the runtime's answer, given by the guest agent,
/// not something read out of the YAML here -- so a fixture without one has to
/// pass validation.
#[cfg(test)]
fn compose_with_health_check(runner: &str, overrides: serde_json::Value) -> AppCompose {
    let mut requirements = serde_json::json!({"health_check": true});
    for (key, value) in overrides.as_object().expect("an object of overrides") {
        requirements[key] = value.clone();
    }
    serde_json::from_value(serde_json::json!({
        "manifest_version": "3",
        "name": "health-app",
        "runner": runner,
        "docker_compose_file": "services:\n  web:\n    image: app:1\n",
        "requirements": requirements,
    }))
    .unwrap()
}

#[test]
fn health_check_on_a_container_runner_needs_no_health_status_file() {
    let compose = compose_with_health_check("docker-compose", serde_json::json!({}));
    verify_manifest_feature_requirements(&compose).unwrap();
}

/// The `bash` runner starts no containers, so the container fallback has
/// nothing to look at and would answer healthy forever. That is exactly the
/// silent no-op the opt-in exists to avoid.
#[test]
fn health_check_without_containers_to_judge_is_rejected() {
    let compose = compose_with_health_check("bash", serde_json::json!({}));
    let err = verify_manifest_feature_requirements(&compose).unwrap_err();
    assert!(
        err.to_string().contains("needs health_status_file"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_bash_runner_with_a_health_status_file_is_accepted() {
    let compose = compose_with_health_check(
        "bash",
        serde_json::json!({"health_status_file": "/dstack/health"}),
    );
    verify_manifest_feature_requirements(&compose).unwrap();
}

/// The agent runs in the guest rootfs, so a relative path resolves against
/// whatever its working directory happens to be.
#[test]
fn a_relative_health_status_file_is_rejected() {
    let compose = compose_with_health_check(
        "docker-compose",
        serde_json::json!({"health_status_file": "health"}),
    );
    let err = verify_manifest_feature_requirements(&compose).unwrap_err();
    assert!(
        err.to_string().contains("absolute path"),
        "unexpected error: {err}"
    );
}

/// Declared but switched off must not be validated as if it were on: turning
/// gating off during an incident should not also have to be a config rewrite.
/// Both of the surviving checks would reject this fixture with the flag on.
#[test]
fn a_disabled_health_check_is_not_validated() {
    let compose = compose_with_health_check(
        "bash",
        serde_json::json!({"health_check": false, "health_status_file": "relative"}),
    );
    verify_manifest_feature_requirements(&compose).unwrap();
}

/// `requirements` is `deny_unknown_fields`, so a guest image that predates the
/// field refuses the deployment instead of ignoring the request.
#[test]
fn an_unknown_requirements_field_is_refused() {
    let parsed = serde_json::from_value::<AppCompose>(serde_json::json!({
        "manifest_version": "3",
        "name": "health-app",
        "runner": "docker-compose",
        "requirements": { "health_check_v2": { "enabled": true } },
    }));
    assert!(
        parsed.is_err(),
        "unknown requirements fields must fail closed"
    );
}

#[test]
fn test_manifest_version_policy_rejects_above_guest_max() {
    let app_compose = test_app_compose(serde_json::json!("4"), None);
    let err = verify_manifest_version(&app_compose).unwrap_err();
    assert!(err.to_string().contains("Unsupported manifest_version"));
}

#[test]
fn test_requirements_require_v3_manifest() {
    let app_compose = test_app_compose(serde_json::json!("2"), Some(&["dstack-tdx"]));
    let err = verify_manifest_feature_requirements(&app_compose).unwrap_err();
    assert!(err.to_string().contains("requires manifest_version"));
}

#[test]
fn test_nerdctl_compose_requires_v3_manifest() {
    let mut app_compose = test_app_compose(serde_json::json!(2), None);
    app_compose.runner = "nerdctl-compose".to_string();
    let err = verify_manifest_feature_requirements(&app_compose).unwrap_err();
    assert!(err.to_string().contains("nerdctl-compose requires"));

    app_compose.manifest_version = "3".to_string();
    verify_manifest_feature_requirements(&app_compose).unwrap();
}

#[test]
fn test_multiple_init_scripts_require_v3_manifest() {
    let mut app_compose = test_app_compose(serde_json::json!(2), None);
    app_compose.init_script = vec!["echo one".into(), "echo two".into()];
    let err = verify_manifest_feature_requirements(&app_compose).unwrap_err();
    assert!(err
        .to_string()
        .contains("multiple init scripts require manifest_version"));

    app_compose.manifest_version = "3".into();
    verify_manifest_feature_requirements(&app_compose).unwrap();
}

#[test]
fn test_snapshotter_is_rejected_for_other_runners() {
    let mut app_compose = test_app_compose(serde_json::json!("3"), None);
    app_compose.snapshotter = Some(dstack_types::ContainerSnapshotter::Stargz);
    let err = verify_manifest_feature_requirements(&app_compose).unwrap_err();
    assert!(err
        .to_string()
        .contains("snapshotter is only supported by the nerdctl-compose runner"));
}

#[test]
fn test_platform_requirements_accept_matching_platform() {
    let app_compose = test_app_compose(
        serde_json::json!("3"),
        Some(&["dstack-gcp-tdx", "dstack-tdx"]),
    );
    verify_platform_requirements(&app_compose, TeeVariant::DstackGcpTdx).unwrap();
    verify_platform_requirements(&app_compose, TeeVariant::DstackTdx).unwrap();
}

#[test]
fn test_platform_requirements_reject_non_matching_platform() {
    let app_compose = test_app_compose(serde_json::json!("3"), Some(&["dstack-gcp-tdx"]));
    let err = verify_platform_requirements(&app_compose, TeeVariant::DstackAmdSevSnp).unwrap_err();
    assert!(err.to_string().contains("Unsupported attestation platform"));
}

#[test]
fn test_platform_requirements_require_v3_manifest() {
    let app_compose = test_app_compose(serde_json::json!("2"), Some(&["dstack-gcp-tdx"]));
    let err = verify_manifest_feature_requirements(&app_compose).unwrap_err();
    assert!(err.to_string().contains("requires manifest_version"));
}

#[test]
fn test_empty_requirements_require_v3_manifest() {
    let app_compose: AppCompose = serde_json::from_value(serde_json::json!({
        "manifest_version": "2",
        "name": "test",
        "runner": "docker-compose",
        "requirements": {}
    }))
    .unwrap();
    let err = verify_manifest_feature_requirements(&app_compose).unwrap_err();
    assert!(err.to_string().contains("requires manifest_version"));
}

#[test]
fn test_platform_requirements_omitted_accepts_any_platform() {
    let app_compose = test_app_compose(serde_json::json!("3"), None);
    verify_platform_requirements(&app_compose, TeeVariant::DstackAmdSevSnp).unwrap();
}

#[test]
fn test_platform_requirements_explicit_empty_rejects_all_platforms() {
    let app_compose = test_app_compose(serde_json::json!("3"), Some(&[]));
    let err = verify_platform_requirements(&app_compose, TeeVariant::DstackTdx).unwrap_err();
    assert!(err.to_string().contains("Unsupported attestation platform"));

    let app_compose = test_app_compose(serde_json::json!("2"), Some(&[]));
    let err = verify_manifest_feature_requirements(&app_compose).unwrap_err();
    assert!(err.to_string().contains("requires manifest_version"));
}

#[test]
fn test_platform_requirements_reject_invalid_platform_value() {
    let app_compose = test_app_compose(serde_json::json!("3"), Some(&["gcptdx"]));
    let err = verify_platform_requirements(&app_compose, TeeVariant::DstackTdx).unwrap_err();
    assert!(err
        .to_string()
        .contains("Invalid requirements.platforms[0]"));
}

#[test]
fn test_tdx_measure_acpi_tables_requirement_matches_vm_config() {
    let app_compose: AppCompose = serde_json::from_value(serde_json::json!({
        "manifest_version": "3",
        "name": "test",
        "runner": "docker-compose",
        "requirements": {
            "tdx_measure_acpi_tables": true
        }
    }))
    .unwrap();
    verify_tdx_measure_acpi_tables_requirement(&app_compose, r#"{}"#, TeeVariant::DstackTdx)
        .unwrap();
    let err = verify_tdx_measure_acpi_tables_requirement(
        &app_compose,
        r#"{"tdx_attestation_variant":"lite"}"#,
        TeeVariant::DstackTdx,
    )
    .unwrap_err();
    assert!(err.to_string().contains("tdx_measure_acpi_tables=true"));

    let app_compose: AppCompose = serde_json::from_value(serde_json::json!({
        "manifest_version": "3",
        "name": "test",
        "runner": "docker-compose",
        "requirements": {
            "tdx_measure_acpi_tables": false
        }
    }))
    .unwrap();
    verify_tdx_measure_acpi_tables_requirement(
        &app_compose,
        r#"{"tdx_attestation_variant":"lite"}"#,
        TeeVariant::DstackTdx,
    )
    .unwrap();
    let err =
        verify_tdx_measure_acpi_tables_requirement(&app_compose, r#"{}"#, TeeVariant::DstackTdx)
            .unwrap_err();
    assert!(err.to_string().contains("tdx_measure_acpi_tables=false"));
}

#[test]
fn test_tdx_measure_acpi_tables_requirement_ignored_on_non_tdx() {
    let app_compose: AppCompose = serde_json::from_value(serde_json::json!({
        "manifest_version": "3",
        "name": "test",
        "runner": "docker-compose",
        "requirements": {
            "tdx_measure_acpi_tables": true
        }
    }))
    .unwrap();
    verify_tdx_measure_acpi_tables_requirement(
        &app_compose,
        r#"{"tdx_attestation_variant":"lite"}"#,
        TeeVariant::DstackAmdSevSnp,
    )
    .unwrap();
}

#[cfg(test)]
const TEST_LAUNCH_TOKEN: &str = "unit-test-launch-token-0000000001";
#[cfg(test)]
// sha256("dstack-launch-token/v1:" || TEST_LAUNCH_TOKEN)
const TEST_LAUNCH_TOKEN_HASH: &str =
    "28faa1319055d733ad9651f5ab7689c15b04609846bcd27b3c5bc8df6246f5a3";

#[test]
fn test_launch_token_requirement_accepts_matching_token() {
    verify_launch_token_requirement(TEST_LAUNCH_TOKEN_HASH, TEST_LAUNCH_TOKEN).unwrap();
}

#[test]
fn test_launch_token_requirement_rejects_wrong_token() {
    let err = verify_launch_token_requirement(
        TEST_LAUNCH_TOKEN_HASH,
        "wrong-launch-token-00000000000001",
    )
    .unwrap_err();
    assert!(err.to_string().contains("launch token mismatch"));
}

#[test]
fn test_launch_token_requirement_rejects_short_token() {
    // sha256("dstack-launch-token/v1:test"): a matching but brute-forceable
    // token must be rejected.
    let err = verify_launch_token_requirement(
        "e128cf5f3c3633d3a1f450d3d4bece260b20f9afb667de4bbff6dd985f1e5d1a",
        "test",
    )
    .unwrap_err();
    assert!(err.to_string().contains("launch token too short"));
    let err = verify_launch_token_requirement(TEST_LAUNCH_TOKEN_HASH, "").unwrap_err();
    assert!(err.to_string().contains("launch token too short"));
    // 31 bytes is one short of the minimum.
    let err = verify_launch_token_requirement(TEST_LAUNCH_TOKEN_HASH, &"a".repeat(31)).unwrap_err();
    assert!(err.to_string().contains("launch token too short"));
}

#[test]
fn test_launch_token_requirement_rejects_invalid_hash() {
    let err = verify_launch_token_requirement("zz", TEST_LAUNCH_TOKEN).unwrap_err();
    assert!(err.to_string().contains("not a hex string"));
    let err = verify_launch_token_requirement("9f86d0", TEST_LAUNCH_TOKEN).unwrap_err();
    assert!(err.to_string().contains("expected 32-byte sha256 hex"));
}

#[test]
fn test_launch_token_from_user_config_extracts_token() {
    let user_config = r#"{"dstack":{"launch_token":"test"},"app":{"foo":"bar"}}"#;
    assert_eq!(launch_token_from_user_config(user_config).unwrap(), "test");
}

#[test]
fn test_launch_token_from_user_config_rejects_missing_or_invalid_token() {
    let err = launch_token_from_user_config(r#"{}"#).unwrap_err();
    assert!(err.to_string().contains("missing dstack.launch_token"));
    let err = launch_token_from_user_config(r#"{"dstack":{}}"#).unwrap_err();
    assert!(err.to_string().contains("missing dstack.launch_token"));
    let err = launch_token_from_user_config(r#"{"dstack":{"launch_token":42}}"#).unwrap_err();
    assert!(err.to_string().contains("not a string"));
    let err = launch_token_from_user_config("not json").unwrap_err();
    assert!(err
        .to_string()
        .contains("failed to parse user_config as JSON"));
}

#[cfg(test)]
mod kms_provider_inventory_tests {
    use super::{kms_rpc_url, validate_key_provider_inputs};
    use dstack_types::KeyProviderKind;

    #[test]
    fn normalizes_kms_rpc_urls_once() {
        assert_eq!(kms_rpc_url("https://kms.test"), "https://kms.test/prpc");
        assert_eq!(kms_rpc_url("https://kms.test/"), "https://kms.test/prpc");
        assert_eq!(
            kms_rpc_url("https://kms.test/prpc"),
            "https://kms.test/prpc"
        );
        assert_eq!(
            kms_rpc_url("https://kms.test/prpc/"),
            "https://kms.test/prpc"
        );
    }

    #[test]
    fn local_key_providers_do_not_require_kms_inventory() {
        let no_urls = Vec::new();
        assert!(validate_key_provider_inputs(KeyProviderKind::Local, &no_urls).is_ok());
        assert!(validate_key_provider_inputs(KeyProviderKind::Tpm, &no_urls).is_ok());
        assert!(validate_key_provider_inputs(KeyProviderKind::None, &no_urls).is_ok());
        let error = validate_key_provider_inputs(KeyProviderKind::Kms, &no_urls).unwrap_err();
        assert!(error.to_string().contains("No KMS URLs are set"));
    }
}

#[cfg(test)]
mod gateway_registration_refresh_tests {
    use super::{
        carry_cluster_preference, gateway_rpc_url, order_by_stickiness, record_accepting_url,
        wireguard_endpoint_hosts, GatewayKeyStore, IssuedClientCerts,
    };
    use std::os::unix::fs::PermissionsExt as _;

    fn key_store(cert_not_after: u64) -> GatewayKeyStore {
        GatewayKeyStore {
            client_cert: "sentinel-client-cert".into(),
            client_cert_with_quote: "sentinel-quoted-cert".into(),
            client_key: "sentinel-client-key".into(),
            cert_not_after,
            wg_sk: "sentinel-wg-private".into(),
            wg_pk: "sentinel-wg-public".into(),
            last_url: None,
        }
    }

    fn urls(list: &[&str]) -> Vec<String> {
        list.iter().map(|url| url.to_string()).collect()
    }

    fn ordered(list: &[String], last: Option<&str>) -> Vec<String> {
        order_by_stickiness(list, last)
            .into_iter()
            .cloned()
            .collect()
    }

    /// With nothing remembered the configured order stands, which is the
    /// behaviour every existing deployment already has.
    #[test]
    fn without_a_remembered_url_the_configured_order_stands() {
        let list = urls(&["https://a", "https://b", "https://c"]);
        assert_eq!(ordered(&list, None), list);
    }

    /// The point: a CVM that moved to the second gateway during an outage stays
    /// there instead of snapping back the moment the first recovers. Each move
    /// rewrites the instance record from a different node's memory.
    #[test]
    fn the_last_accepting_url_is_tried_first() {
        let list = urls(&["https://a", "https://b", "https://c"]);
        assert_eq!(
            ordered(&list, Some("https://b")),
            urls(&["https://b", "https://a", "https://c"])
        );
    }

    /// A preference, not a pin: if the remembered one is down it costs one
    /// failed attempt and the rest follow in configured order.
    #[test]
    fn the_remaining_urls_keep_their_configured_order() {
        let list = urls(&["https://a", "https://b", "https://c", "https://d"]);
        assert_eq!(
            ordered(&list, Some("https://c")),
            urls(&["https://c", "https://a", "https://b", "https://d"])
        );
    }

    /// An operator removing a URL from the config must not resurrect it.
    #[test]
    fn a_remembered_url_no_longer_configured_is_ignored() {
        let list = urls(&["https://a", "https://b"]);
        assert_eq!(ordered(&list, Some("https://gone")), list);
    }

    #[test]
    fn every_url_is_tried_exactly_once() {
        let list = urls(&["https://a", "https://b", "https://c"]);
        for last in [
            None,
            Some("https://a"),
            Some("https://b"),
            Some("https://c"),
        ] {
            let mut seen = ordered(&list, last);
            assert_eq!(seen.len(), list.len(), "last={last:?}");
            seen.sort();
            let mut expected = list.clone();
            expected.sort();
            assert_eq!(seen, expected, "last={last:?}");
        }
    }

    /// The cache is what carries the preference across a refresh, so it has to
    /// survive the round trip -- and an older cache without the field must
    /// still load.
    #[test]
    fn the_remembered_url_round_trips_through_the_cache() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gateway-cache.json");
        let mut store = key_store(u64::MAX);
        store.last_url = Some("https://b".into());
        store.save_to(&path).expect("save");
        let loaded = GatewayKeyStore::load_from(&path).expect("load");
        assert_eq!(loaded.last_url.as_deref(), Some("https://b"));

        let legacy = serde_json::to_value(key_store(u64::MAX))
            .map(|mut value| {
                value.as_object_mut().unwrap().remove("last_url");
                value
            })
            .expect("serialize");
        std::fs::write(&path, legacy.to_string()).expect("write");
        let loaded =
            GatewayKeyStore::load_from(&path).expect("a cache without the field must load");
        assert_eq!(loaded.last_url, None);
    }

    fn issued_certs(cert_not_after: u64) -> IssuedClientCerts {
        IssuedClientCerts {
            client_cert: "renewed-cert".into(),
            client_cert_with_quote: "renewed-cert-with-quote".into(),
            client_key: "renewed-key".into(),
            cert_not_after,
        }
    }

    /// A certificate renewal rebuilds the store from scratch. It must carry
    /// the WireGuard identity — the gateway maps this peer by its public
    /// key — and the registration preference, or every renewal would drift
    /// the CVM back onto the first configured URL.
    #[test]
    fn a_certificate_renewal_carries_the_wireguard_identity_and_the_preference() {
        let mut cached = key_store(0);
        cached.last_url = Some("https://b".into());
        let renewed = GatewayKeyStore::renewed(
            Some(cached),
            || panic!("a cached WireGuard identity must be reused, not regenerated"),
            issued_certs(u64::MAX),
        )
        .expect("renew");
        assert_eq!(renewed.wg_sk, "sentinel-wg-private");
        assert_eq!(renewed.wg_pk, "sentinel-wg-public");
        assert_eq!(renewed.last_url.as_deref(), Some("https://b"));
        assert_eq!(renewed.client_cert, "renewed-cert");
        assert_eq!(renewed.cert_not_after, u64::MAX);
    }

    /// A cold start has nothing to carry: fresh WireGuard identity, no
    /// preference.
    #[test]
    fn a_cold_start_generates_a_fresh_wireguard_identity_and_no_preference() {
        let renewed = GatewayKeyStore::renewed(
            None,
            || Ok(("fresh-wg-private".into(), "fresh-wg-public".into())),
            issued_certs(u64::MAX),
        )
        .expect("renew");
        assert_eq!(renewed.wg_sk, "fresh-wg-private");
        assert_eq!(renewed.wg_pk, "fresh-wg-public");
        assert_eq!(renewed.last_url, None);
    }

    /// The sequence a refresh tick runs for the default cluster when the
    /// certificate expires: rebuild the store, save it over the cache, then
    /// read the preference back for the registration round. The rebuilt store
    /// is what gets written, so it must already carry the preference — this
    /// is exactly the sequence that used to lose it.
    #[test]
    fn the_preference_survives_the_renewal_that_rewrites_the_cache() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gateway-cache.json");
        let mut cached = key_store(0); // expired certificate forces the rebuild
        cached.last_url = Some("https://b".into());
        cached.save_to(&path).expect("save");

        let renewed = GatewayKeyStore::renewed(
            GatewayKeyStore::load_from(&path),
            || panic!("a cached WireGuard identity must be reused, not regenerated"),
            issued_certs(u64::MAX),
        )
        .expect("renew");
        renewed.save_to(&path).expect("save renewed");

        let mut store = renewed;
        carry_cluster_preference(&mut store, &path, &urls(&["https://a", "https://b"]));
        assert_eq!(store.last_url.as_deref(), Some("https://b"));
    }

    /// An additional cluster's store is cloned from the primary's; the
    /// preference that counts is the one in the cluster's own cache.
    #[test]
    fn an_additional_cluster_does_not_inherit_the_primary_preference() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gateway-cache-second.json");
        let mut cluster_cache = key_store(u64::MAX);
        cluster_cache.last_url = Some("https://b".into());
        cluster_cache.save_to(&path).expect("save");

        let mut store = key_store(u64::MAX);
        store.last_url = Some("https://primary".into());
        carry_cluster_preference(&mut store, &path, &urls(&["https://a", "https://b"]));
        assert_eq!(store.last_url.as_deref(), Some("https://b"));
    }

    /// No cache on disk means no preference, whatever the resolved store
    /// happened to carry.
    #[test]
    fn a_missing_cluster_cache_clears_the_carried_preference() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("absent.json");
        let mut store = key_store(u64::MAX);
        store.last_url = Some("https://primary".into());
        carry_cluster_preference(&mut store, &path, &urls(&["https://primary"]));
        assert_eq!(store.last_url, None);
    }

    /// An operator removing a URL from the config must not see the cache
    /// resurrect it.
    #[test]
    fn the_carry_drops_a_url_removed_from_the_config() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gateway-cache.json");
        let mut cached = key_store(u64::MAX);
        cached.last_url = Some("https://gone".into());
        cached.save_to(&path).expect("save");

        let mut store = key_store(u64::MAX);
        carry_cluster_preference(&mut store, &path, &urls(&["https://a"]));
        assert_eq!(store.last_url, None);
    }

    /// Only an acceptance updates the preference: a round where every URL
    /// failed says nothing about where the instance record lives, and
    /// clearing on it would erase the fleet's spread in one bad tick.
    #[test]
    fn a_round_where_every_url_failed_keeps_the_preference() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gateway-cache.json");
        let mut store = key_store(u64::MAX);
        store.last_url = Some("https://b".into());
        store.save_to(&path).expect("save");

        record_accepting_url("default", &mut store, &path, None);
        assert_eq!(store.last_url.as_deref(), Some("https://b"));
        let on_disk = GatewayKeyStore::load_from(&path).expect("load");
        assert_eq!(on_disk.last_url.as_deref(), Some("https://b"));
    }

    /// An acceptance by a different node is recorded in memory and on disk.
    #[test]
    fn an_acceptance_moves_and_persists_the_preference() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gateway-cache.json");
        let mut store = key_store(u64::MAX);
        store.last_url = Some("https://a".into());

        record_accepting_url("default", &mut store, &path, Some("https://c".into()));
        assert_eq!(store.last_url.as_deref(), Some("https://c"));
        let on_disk = GatewayKeyStore::load_from(&path).expect("load");
        assert_eq!(on_disk.last_url.as_deref(), Some("https://c"));
    }

    /// The first acceptance of a boot is recorded too — that is what the
    /// next refresh's ordering is built from.
    #[test]
    fn the_first_acceptance_is_recorded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gateway-cache.json");
        let mut store = key_store(u64::MAX);

        record_accepting_url("default", &mut store, &path, Some("https://a".into()));
        assert_eq!(store.last_url.as_deref(), Some("https://a"));
        let on_disk = GatewayKeyStore::load_from(&path).expect("load");
        assert_eq!(on_disk.last_url.as_deref(), Some("https://a"));
    }

    /// Re-acceptance by the remembered node changes nothing, so nothing is
    /// written.
    #[test]
    fn re_acceptance_by_the_same_url_does_not_rewrite_the_cache() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gateway-cache.json");
        let mut store = key_store(u64::MAX);
        store.last_url = Some("https://c".into());

        record_accepting_url("default", &mut store, &path, Some("https://c".into()));
        assert_eq!(store.last_url.as_deref(), Some("https://c"));
        assert!(
            !path.exists(),
            "an unchanged preference must not be written"
        );
    }

    #[test]
    fn gateway_rpc_urls_are_normalized_once() {
        assert_eq!(
            gateway_rpc_url("https://gateway.test"),
            "https://gateway.test/prpc"
        );
        assert_eq!(
            gateway_rpc_url("https://gateway.test/"),
            "https://gateway.test/prpc"
        );
        assert_eq!(
            gateway_rpc_url("https://gateway.test/prpc"),
            "https://gateway.test/prpc"
        );
        assert_eq!(
            gateway_rpc_url("https://gateway.test/prpc/"),
            "https://gateway.test/prpc"
        );
    }

    #[test]
    fn key_store_round_trip_is_private_and_stable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway-cache.json");
        let original = key_store(10_000);
        original.save_to(&path).unwrap();
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        let loaded = GatewayKeyStore::load_from(&path).unwrap();
        assert_eq!(loaded.wg_sk, original.wg_sk);
        assert_eq!(loaded.wg_pk, original.wg_pk);
        assert_eq!(loaded.client_key, original.client_key);
    }

    #[test]
    fn malformed_replacement_does_not_overwrite_working_cache() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway-cache.json");
        let original = key_store(10_000);
        original.save_to(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let invalid_target = directory.path().join("missing-parent/cache.json");
        assert!(key_store(20_000).save_to(&invalid_target).is_ok());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::write(&path, b"not-json").unwrap();
        assert!(GatewayKeyStore::load_from(&path).is_none());
    }

    #[test]
    fn certificate_refresh_boundary_is_strict_and_overflow_safe() {
        assert!(key_store(1_601).is_cert_valid_at(1_000));
        assert!(!key_store(1_600).is_cert_valid_at(1_000));
        assert!(!key_store(u64::MAX).is_cert_valid_at(u64::MAX));
    }

    #[test]
    fn wireguard_endpoint_hosts_support_dns_ipv4_and_ipv6() {
        let config = r#"
Endpoint = gateway.example.com:51820
Endpoint = 192.0.2.1:51821
Endpoint = [2001:db8::1]:51822
"#;
        assert_eq!(
            wireguard_endpoint_hosts(config).unwrap(),
            ["gateway.example.com", "192.0.2.1", "2001:db8::1"]
        );
        assert!(wireguard_endpoint_hosts("Endpoint = missing-port").is_err());
    }
}
