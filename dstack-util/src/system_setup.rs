// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use dstack_attest::emit_runtime_event;
use dstack_kms_rpc as rpc;
use dstack_types::{
    shared_filenames::{
        APP_COMPOSE, APP_KEYS, DECRYPTED_ENV, DECRYPTED_ENV_JSON, ENCRYPTED_ENV,
        HOST_SHARED_DIR_NAME, HOST_SHARED_DISK_LABEL, INSTANCE_INFO, SEALED_ENV, SYS_CONFIG,
        USER_CONFIG,
    },
    KeyProvider, KeyProviderInfo,
};
use fs_err as fs;
use ra_rpc::{
    client::{CertInfo, RaClient, RaClientConfig},
    Attestation,
};
use ra_tls::{
    attestation::QuoteContentType,
    cert::{generate_ra_cert, CertConfigV2, CertSigningRequestV2, Csr},
};
use rand::Rng as _;
use safe_write::safe_write_with_mode;
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    cmd_show_mrs,
    crypto::dh_decrypt,
    gen_app_keys_from_seed,
    host_api::HostApi,
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
mod luks;
use luks::{load_luks_header, sync_luks_epochs, write_luks_epochs, PAYLOAD_OFFSET};
mod sealed_env;
#[cfg(test)]
use sealed_env::seal_env;
use sealed_env::{env_crypt_key, seal_env_at_epochs, sealed_env_info_at_epochs, SealedEnv};

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

    fn sealed_env_file(&self) -> PathBuf {
        self.base_dir.join(SEALED_ENV)
    }

    fn sys_config_file(&self) -> PathBuf {
        self.base_dir.join(SYS_CONFIG)
    }

    fn instance_info_file(&self) -> PathBuf {
        self.base_dir.join(INSTANCE_INFO)
    }
}

fn env_file_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => bail!("env {} is not a regular file", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect env {}", path.display()))
        }
    }
}

fn read_optional_env(path: &Path) -> Result<Option<Vec<u8>>> {
    if !env_file_exists(path)? {
        return Ok(None);
    }
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read env {}", path.display())),
    }
}

struct HostShared {
    dir: HostShareDir,
    sys_config: SysConfig,
    app_compose: AppCompose,
    encrypted_env: Vec<u8>,
    sealed_env: Option<Vec<u8>>,
    instance_info: InstanceInfo,
}

impl HostShared {
    /// Find block device by volume label
    fn find_disk_by_label(label: &str) -> Option<String> {
        let label_path = format!("/dev/disk/by-label/{}", label);
        if Path::new(&label_path).exists() {
            return Some(label_path);
        }

        // Fallback: scan /sys/block for devices and check their labels with blkid
        if let Ok(entries) = fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let dev_name = entry.file_name();
                let dev_path = format!("/dev/{}", dev_name.to_string_lossy());

                // Use blkid to check the label
                if let Ok(output) = Command::new("blkid")
                    .arg("-s")
                    .arg("LABEL")
                    .arg("-o")
                    .arg("value")
                    .arg(&dev_path)
                    .output()
                {
                    if output.status.success() {
                        let found_label =
                            String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if found_label == label {
                            return Some(dev_path);
                        }
                    }
                }
            }
        }

        None
    }

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
        let sealed_env = read_optional_env(&host_shared_dir.sealed_env_file())?;
        let encrypted_env = if sealed_env.is_some() {
            Vec::new()
        } else {
            read_optional_env(&host_shared_dir.encrypted_env_file())?.unwrap_or_default()
        };
        Ok(Self {
            dir: host_shared_dir.clone(),
            sys_config,
            app_compose,
            encrypted_env,
            sealed_env,
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
            use fs::os::unix::fs::OpenOptionsExt;
            use std::io::Read;
            // O_NONBLOCK: opening a FIFO on the host share must not block the boot.
            let src_io = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(src_path)?;
            if !src_io.metadata()?.is_file() {
                bail!("Source file {src} is not a regular file");
            }
            let mut dst_io = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(dst_path)?;
            let copied = std::io::copy(&mut src_io.take(max_size + 1), &mut dst_io)?;
            if copied > max_size {
                bail!("Source file {src} is too large, max size is {max_size} bytes");
            }
            Ok(())
        };
        cmd! {
            info "Mounting host-shared";
            mkdir -p $host_shared_dir;
        }?;

        // The host composes this filesystem. Nothing on it is executed and
        // nothing on it is a device node: the guest copies a few regular files
        // off it and unmounts it, so refuse set-user-ID bits, devices and exec.
        //
        // Try to detect and mount shared disk by label first, fallback to 9p
        let disk_device = Self::find_disk_by_label(HOST_SHARED_DISK_LABEL);
        let mounted_via_disk = if let Some(dev) = disk_device {
            info!("Found shared disk at {}", dev);
            let mount_result = cmd! {
                info "Attempting to mount shared disk";
                mount -o ro,nosuid,nodev,noexec $dev $host_shared_dir;
            };
            mount_result.is_ok()
        } else {
            false
        };

        if !mounted_via_disk {
            info!("Shared disk not found, trying 9p virtfs");
            cmd! {
                mount -t 9p -o trans=virtio,version=9p2000.L,ro,nosuid,nodev,noexec host-shared $host_shared_dir;
            }?;
        } else {
            info!("Successfully mounted shared disk");
        }

        cmd! {
            mkdir -p $host_shared_copy_dir;
            info "Copying host-shared files";
        }?;
        copy(APP_COMPOSE, SZ_1KB * 256, false)?;
        copy(SYS_CONFIG, SZ_1KB * 32, false)?;
        copy(INSTANCE_INFO, SZ_1KB * 10, true)?;
        if env_file_exists(&host_shared_dir.join(SEALED_ENV))? {
            copy(SEALED_ENV, SZ_1KB * 384, false)?;
        } else {
            match fs::remove_file(host_shared_copy_dir.join(SEALED_ENV)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("failed to remove stale sealed env copy"),
            }
            copy(ENCRYPTED_ENV, SZ_1KB * 256, true)?;
        }
        copy(USER_CONFIG, SZ_1MB, true)?;
        cmd! {
            info "Unmounting host-shared";
            umount $host_shared_dir;
        }?;
        HostShared::load(host_shared_copy_dir)
    }

    /// Request app keys from one KMS, of the given (root, app) epochs or the
    /// current ones when `epochs` is `None`.
    ///
    /// Only the request for the current keys extends RTMR3 and takes the KMS
    /// root CA from the KMS; a request for older epochs pins `trusted_ca`, the
    /// CA this boot already established, and the CA of those epochs that the
    /// KMS returns is not trusted for anything.
    async fn request_app_keys_from_kms_url(
        &self,
        kms_url: String,
        epochs: Option<(u32, u32)>,
        trusted_ca: Option<String>,
    ) -> Result<AppKeys> {
        info!("Requesting app keys of epochs {epochs:?} from KMS: {kms_url}");
        let measure = trusted_ca.is_none();
        let tmp_ca = {
            info!("Getting temp ca cert");
            let client = RaClient::new(kms_url.clone(), true)?;
            let kms_client = dstack_kms_rpc::kms_client::KmsClient::new(client);
            kms_client
                .get_temp_ca_cert()
                .await
                .context("Failed to get temp ca cert")?
        };
        let root_ca = trusted_ca.unwrap_or(tmp_ca.ca_cert);
        let cert_pair = generate_ra_cert(tmp_ca.temp_ca_cert.clone(), tmp_ca.temp_ca_key.clone())?;
        let ra_client = RaClientConfig::builder()
            .tls_no_check(false)
            .tls_built_in_root_certs(false)
            .remote_uri(kms_url.clone())
            .tls_client_cert(cert_pair.cert_pem)
            .tls_client_key(cert_pair.key_pem)
            .tls_ca_cert(root_ca.clone())
            .maybe_pccs_url(self.sys_config.pccs_url.clone())
            .cert_validator(Box::new(move |cert| {
                let Some(cert) = cert else {
                    bail!("Missing server cert");
                };
                let Some(usage) = cert.special_usage else {
                    bail!("Missing server cert usage");
                };
                if usage != "kms:rpc" {
                    bail!("Invalid server cert usage: {usage}");
                }
                if let Some(att) = cert.attestation.as_ref().filter(|_| measure) {
                    let kms_info = att
                        .decode_app_info(false)
                        .context("Failed to decode app_info")?;
                    emit_runtime_event("mr-kms", &kms_info.mr_aggregated)
                        .context("Failed to extend mr-kms to RTMR3")?;
                }
                Ok(())
            }))
            .build()
            .into_client()
            .context("Failed to create client")?;
        let kms_client = dstack_kms_rpc::kms_client::KmsClient::new(ra_client);
        let response = kms_client
            .get_app_key(rpc::GetAppKeyRequest {
                api_version: 1,
                vm_config: self.sys_config.vm_config.clone(),
                root_epoch: epochs.map(|(root, _)| root),
                app_epoch: epochs.map(|(_, app)| app),
            })
            .await
            .context("Failed to get app key")?;
        if let Some((root, app)) = epochs {
            if (response.root_epoch, response.app_epoch) != (root, app) {
                bail!(
                    "KMS returned epochs ({}, {}) instead of the requested ({root}, {app})",
                    response.root_epoch,
                    response.app_epoch
                );
            }
        }

        if measure {
            emit_runtime_event("os-image-hash", &response.os_image_hash)
                .context("Failed to extend os-image-hash to RTMR3")?;
        }

        let (_, ca_pem) = x509_parser::pem::parse_x509_pem(root_ca.as_bytes())
            .context("Failed to parse ca cert")?;
        let x509 = ca_pem.parse_x509().context("Failed to parse ca cert")?;
        let root_pubkey = x509.public_key().raw.to_vec();

        Ok(AppKeys {
            ca_cert: root_ca,
            disk_crypt_key: response.disk_crypt_key,
            env_crypt_key: response.env_crypt_key,
            sealed_env_key: response.sealed_env_key,
            k256_key: response.k256_key,
            k256_signature: response.k256_signature,
            gateway_app_id: response.gateway_app_id,
            key_provider: KeyProvider::Kms {
                url: kms_url,
                pubkey: root_pubkey,
                tmp_ca_key: tmp_ca.temp_ca_key,
                tmp_ca_cert: tmp_ca.temp_ca_cert,
                root_epoch: response.root_epoch,
                app_epoch: response.app_epoch,
            },
        })
    }

    /// Request the app keys of older epochs from the KMS that served `keys`.
    async fn request_historical_keys(
        &self,
        keys: &AppKeys,
        root: u32,
        app: u32,
    ) -> Result<AppKeys> {
        let KeyProvider::Kms { url, .. } = &keys.key_provider else {
            bail!("only KMS-provided keys have older epochs");
        };
        self.request_app_keys_from_kms_url(
            url.clone(),
            Some((root, app)),
            Some(keys.ca_cert.clone()),
        )
        .await
        .with_context(|| {
            format!(
                "failed to get the keys of root epoch {root}, app epoch {app}; \
                     the policy of those epochs must still allow this instance"
            )
        })
    }
}

// The gateway's WireGuard fields are rendered into a wg-quick config, and
// wg-quick runs its `PreUp`/`PostUp` hooks as root. Accept only values that
// cannot carry config syntax, so the gateway cannot inject lines.
fn parse_wg_ip(ip: &str) -> Result<Ipv4Addr> {
    ip.parse()
        .with_context(|| format!("invalid WireGuard address: {ip:?}"))
}

fn parse_wg_public_key(key: &str) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let decoded = STANDARD
        .decode(key)
        .ok()
        .filter(|decoded| decoded.len() == 32)
        .with_context(|| format!("invalid WireGuard public key: {key:?}"))?;
    Ok(STANDARD.encode(decoded))
}

fn validate_wg_endpoint(endpoint: &str) -> Result<&str> {
    let valid = endpoint.rsplit_once(':').is_some_and(|(host, port)| {
        let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(v6) => v6.parse::<Ipv6Addr>().is_ok(),
            None => {
                !host.is_empty()
                    && host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            }
        };
        host_ok && port.parse::<u16>().is_ok()
    });
    if !valid {
        bail!("invalid WireGuard endpoint: {endpoint:?}");
    }
    Ok(endpoint)
}

const GATEWAY_CACHE_PATH: &str = "/run/dstack/gateway-cache.json";
const WG_CONFIG_PATH: &str = "/etc/wireguard/dstack-wg0.conf";
/// Certificate validity period in seconds (10 days)
const CERT_VALIDITY_SECS: u64 = 10 * 24 * 3600;

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
}

impl GatewayKeyStore {
    fn load() -> Option<Self> {
        let content = fs::read_to_string(GATEWAY_CACHE_PATH).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn save(&self) -> Result<()> {
        let content = serde_json::to_string(self).context("Failed to serialize gateway cache")?;
        safe_write_with_mode(GATEWAY_CACHE_PATH, &content, 0o600)
            .context("Failed to write gateway cache")?;
        Ok(())
    }

    fn is_cert_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Valid if at least 10 minutes remaining
        now + 600 < self.cert_not_after
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
    ) -> Result<GatewayClient<RaClient>> {
        let url = format!("{}/prpc", gateway_url);
        let ca_cert = self.keys.ca_cert.clone();
        let cert_validator = AppIdValidator {
            allowed_app_id: self.keys.gateway_app_id.clone(),
        };
        let client = RaClientConfig::builder()
            .remote_uri(url)
            .maybe_pccs_url(self.shared.sys_config.pccs_url.clone())
            .tls_client_cert(client_cert.to_string())
            .tls_client_key(client_key.to_string())
            .tls_ca_cert(ca_cert)
            .tls_built_in_root_certs(false)
            .tls_no_check(self.keys.gateway_app_id == "any")
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
        let client =
            self.create_gateway_client(gateway_url, &key_store.client_key, &key_store.client_cert)?;
        let result = client
            .register_cvm(RegisterCvmRequest {
                client_public_key: key_store.wg_pk.clone(),
                port_policy: Some(port_policy.clone()),
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
        )?;
        client
            .register_cvm(RegisterCvmRequest {
                client_public_key: key_store.wg_pk.clone(),
                port_policy: Some(port_policy),
            })
            .await
            .context("Failed to register CVM")
    }

    async fn get_or_generate_key_store(&self) -> Result<GatewayKeyStore> {
        // Try to load existing cache
        let cache = GatewayKeyStore::load();

        // If cache is fully valid, return it
        if let Some(ref cache) = cache {
            if cache.is_cert_valid() {
                info!("Using cached gateway key store");
                return Ok(cache.clone());
            }
        }

        // Reuse WireGuard keys from cache if available, otherwise generate new ones
        let (wg_sk, wg_pk) = if let Some(ref cache) = cache {
            info!("Reusing cached WireGuard keys");
            (cache.wg_sk.clone(), cache.wg_pk.clone())
        } else {
            info!("Generating new WireGuard keys");
            let sk = cmd!(wg genkey)?;
            let pk =
                cmd!(echo $sk | wg pubkey).or(Err(anyhow!("Failed to generate public key")))?;
            (sk, pk)
        };

        // Request new client certificates
        info!("Requesting new client certificates");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cert_not_after = now + CERT_VALIDITY_SECS;
        let cert_client = CertRequestClient::create(
            self.keys,
            self.shared.sys_config.pccs_url.as_deref(),
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

        Ok(GatewayKeyStore {
            client_cert,
            client_cert_with_quote,
            client_key,
            cert_not_after,
            wg_sk,
            wg_pk,
        })
    }

    async fn setup(&self, force: bool) -> Result<()> {
        if !self.shared.app_compose.gateway_enabled() {
            info!("dstack-gateway is not enabled");
            return Ok(());
        }
        if self.keys.gateway_app_id.is_empty() {
            bail!("Missing allowed dstack-gateway app id");
        }

        info!("Setting up dstack-gateway");

        // Get or generate key store (includes WireGuard keys and client certificate)
        let key_store = self.get_or_generate_key_store().await?;

        if self.shared.sys_config.gateway_urls.is_empty() {
            bail!("Missing gateway urls");
        }
        // Read config and make API call
        let response = 'out: {
            let mut error = anyhow!("unknown error");
            for (i, url) in self.shared.sys_config.gateway_urls.iter().enumerate() {
                let response = self.register_cvm(url, &key_store).await;
                match response {
                    Ok(response) => {
                        break 'out response;
                    }
                    Err(err) => {
                        warn!("Failed to register CVM: {err:?}, retrying with next dstack-gateway");
                        if i == 0 {
                            error = err;
                        }
                    }
                }
            }
            return Err(error).context("Failed to register CVM, all dstack-gateway urls are down");
        };
        let mut wg_info = response.wg.context("Missing wg info")?;

        let client_ip = parse_wg_ip(&wg_info.client_ip)?;

        // Sort peers by public key for consistent config generation
        wg_info.servers.sort_by(|a, b| a.pk.cmp(&b.pk));

        // Create WireGuard config
        let wg_listen_port = "9182";
        let mut new_config = format!(
            "[Interface]\n\
            PrivateKey = {}\n\
            ListenPort = {wg_listen_port}\n\
            Address = {client_ip}/32\n\n",
            key_store.wg_sk
        );
        for WireGuardPeer { pk, ip, endpoint } in &wg_info.servers {
            let pk = parse_wg_public_key(pk)?;
            let ip = parse_wg_ip(ip.split('/').next().unwrap_or_default())?;
            let endpoint = validate_wg_endpoint(endpoint)?;
            new_config.push_str(&format!(
                "[Peer]\n\
                PublicKey = {pk}\n\
                AllowedIPs = {ip}/32\n\
                Endpoint = {endpoint}\n\
                PersistentKeepalive = 25\n",
            ));
        }

        // Save cache
        if let Err(e) = key_store.save() {
            warn!("Failed to save gateway cache: {e:?}");
        }

        // Check if config has changed (skip check if force is set)
        if !force {
            let current_config = fs::read_to_string(WG_CONFIG_PATH).ok();
            if current_config.as_ref() == Some(&new_config) {
                info!("WireGuard config unchanged, skipping reconfiguration");
                return Ok(());
            }
        }

        safe_write_with_mode(WG_CONFIG_PATH, &new_config, 0o600)
            .context("Failed to write WireGuard config")?;

        cmd! {
            ignore wg-quick down dstack-wg0;
        }?;

        // Setup WireGuard iptables rules
        cmd! {
            // Create the chain if it doesn't exist
            ignore iptables -N DSTACK_WG 2>/dev/null;
            // Flush the chain
            iptables -F DSTACK_WG;
            // Remove any existing jump rule
            ignore iptables -D INPUT -p udp --dport $wg_listen_port -j DSTACK_WG 2>/dev/null;
            // Insert the new jump rule at the beginning of the INPUT chain
            iptables -I INPUT -p udp --dport $wg_listen_port -j DSTACK_WG
        }?;

        for peer in &wg_info.servers {
            // Avoid issues with field-access in the macro by binding the IP to a local variable.
            let endpoint_ip = peer
                .endpoint
                .split(':')
                .next()
                .context("Invalid wireguard endpoint")?;
            cmd!(iptables -A DSTACK_WG -s $endpoint_ip -j ACCEPT)?;
        }

        // Drop any UDP packets that don't come from an allowed IP.
        cmd!(iptables -A DSTACK_WG -j DROP)?;

        info!("Starting WireGuard");
        cmd!(wg-quick up dstack-wg0)?;
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

fn emit_key_provider_info(provider_info: &KeyProviderInfo) -> Result<()> {
    info!("Key provider info: {provider_info:?}");
    let provider_info_json = serde_json::to_vec(&provider_info)?;
    emit_runtime_event("key-provider", &provider_info_json)?;
    Ok(())
}

pub async fn cmd_sys_setup(args: SetupArgs) -> Result<()> {
    let stage0 = Stage0::load(&args)?;
    let vmm = stage0.host_api();
    let result = do_sys_setup(stage0).await;
    if let Err(err) = &result {
        vmm.notify_q("boot.error", &format!("{err:#}")).await;
    }
    result
}

async fn do_sys_setup(stage0: Stage0<'_>) -> Result<()> {
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

pub async fn cmd_gateway_refresh(args: GatewayRefreshArgs) -> Result<()> {
    let host_shared_dir = args.work_dir.join(HOST_SHARED_DIR_NAME);
    let shared = HostShared::load(host_shared_dir.as_path()).with_context(|| {
        format!(
            "Failed to load host-shared dir: {}",
            host_shared_dir.display()
        )
    })?;
    let keys_path = shared.dir.join(APP_KEYS);
    let keys: AppKeys = deserialize_json_file(&keys_path)
        .with_context(|| format!("Failed to load app keys from {}", keys_path.display()))?;

    GatewayContext::new(&shared, &keys).setup(args.force).await
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

impl<'a> Stage0<'a> {
    fn host_api(&self) -> HostApi {
        HostApi::new(
            self.shared.sys_config.host_api_url.clone(),
            self.shared.sys_config.pccs_url.clone(),
        )
    }
    fn load(args: &'a SetupArgs) -> Result<Self> {
        let host_shared_copy_dir = args.work_dir.join(HOST_SHARED_DIR_NAME);
        let host_shared = HostShared::copy("/tmp/.host-shared".as_ref(), &host_shared_copy_dir)?;
        let host_api = HostApi::new(
            host_shared.sys_config.host_api_url.clone(),
            host_shared.sys_config.pccs_url.clone(),
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

    async fn request_app_keys_from_kms(&self) -> Result<AppKeys> {
        if self.shared.sys_config.kms_urls.is_empty() {
            bail!("No KMS URLs are set");
        }
        let keys = 'out: {
            let mut error = anyhow!("unknown error");
            for (i, kms_url) in self.shared.sys_config.kms_urls.iter().enumerate() {
                let kms_url = format!("{kms_url}/prpc");
                let response = self
                    .shared
                    .request_app_keys_from_kms_url(kms_url.clone(), None, None)
                    .await;
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

    async fn request_app_keys(&self) -> Result<AppKeys> {
        let key_provider = self.shared.app_compose.key_provider();
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
                bail!("Tpm key provider is not supported");
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

    async fn mount_data_disk(&self, keys: &AppKeys, opts: &DstackOptions) -> Result<()> {
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
                self.luks_setup(keys, name).await?;
            } else {
                info!("Skipping disk encryption as requested by kernel cmdline");
            }

            match opts.storage_fs {
                FsType::Zfs => {
                    info!("Creating ZFS filesystem");
                    cmd! {
                        zpool create -o autoexpand=on dstack $fs_dev;
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
                self.open_encrypted_volume(keys, name).await?;
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

    async fn luks_setup(&self, keys: &AppKeys, name: &str) -> Result<()> {
        let root_hd = &self.args.device;
        let disk_crypt_key = hex::encode(&keys.disk_crypt_key);
        let sector_offset = PAYLOAD_OFFSET / 512;
        cmd! {
            info "Formatting encrypted disk";
            echo -n $disk_crypt_key |
                cryptsetup luksFormat
                    --type luks2
                    --offset $sector_offset
                    --cipher aes-xts-plain64
                    --pbkdf pbkdf2
                    -d-
                    $root_hd
                    $name;
        }
        .or(Err(anyhow!("Failed to setup luks volume")))?;
        // An epoch-0 disk carries no token, so older OS images still accept it.
        if let Some(root) = kms_root_epoch(keys).filter(|root| *root > 0 || keys.app_epoch() > 0) {
            write_luks_epochs(root_hd, 0, root, keys.app_epoch())?;
        }
        self.open_encrypted_volume(keys, name).await
    }

    /// Open the data disk after bringing it to the current key epochs.
    async fn open_encrypted_volume(&self, keys: &AppKeys, name: &str) -> Result<()> {
        let root_hd = &self.args.device;
        let disk_crypt_key = hex::encode(&keys.disk_crypt_key);
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
        }
        .context("Failed to mount tmpfs for the LUKS2 header")?;

        let hdr = Path::new(&in_mem_hdr);
        let header = load_luks_header(root_hd, hdr)?;
        if let Some(current) = kms_root_epoch(keys) {
            let old_key = async |root, app| {
                let old = self.shared.request_historical_keys(keys, root, app).await?;
                Ok(hex::encode(&old.disk_crypt_key))
            };
            let target = (current, keys.app_epoch());
            sync_luks_epochs(root_hd, hdr, header, &disk_crypt_key, target, old_key)
                .await
                .context("failed to migrate the data disk key")?;
        }

        cmd! {
            info "Opening the device";
            echo -n $disk_crypt_key | cryptsetup luksOpen --type luks2 --header $in_mem_hdr -d- $root_hd $name;
        }
        .or(Err(anyhow!("Failed to open encrypted data disk")))?;

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

    fn measure_app_info(&self) -> Result<AppInfo> {
        let compose_hash = sha256_file(self.shared.dir.app_compose_file())?;
        let truncated_compose_hash = truncate(&compose_hash, 20);
        let kms_enabled = self.shared.app_compose.kms_enabled();
        let key_provider = self.shared.app_compose.key_provider();
        let mut instance_info = self.shared.instance_info.clone();

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
        if (!disk_reusable) || instance_info.instance_id_seed.is_empty() {
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
            sha256(&id_path)[..20].to_vec()
        };
        instance_info.instance_id = instance_id.clone();
        let app_id = if kms_enabled {
            instance_info.app_id.clone()
        } else {
            truncated_compose_hash.to_vec()
        };

        emit_runtime_event("system-preparing", &[])?;
        emit_runtime_event("app-id", &app_id)?;
        emit_runtime_event("compose-hash", &compose_hash)?;
        emit_runtime_event("instance-id", &instance_id)?;
        emit_runtime_event("boot-mr-done", &[])?;
        Ok(AppInfo {
            instance_info,
            compose_hash,
        })
    }

    fn verify_app(&self, app_info: &AppInfo, keys: &AppKeys) -> Result<()> {
        config_id_verifier::verify_mr_config_id(
            &app_info.compose_hash,
            &app_info
                .instance_info
                .app_id
                .as_slice()
                .try_into()
                .ok()
                .context("Invalid app id")?,
            keys.key_provider.kind(),
            keys.key_provider.id(),
        )?;
        self.verify_key_provider_id(keys.key_provider.id())?;
        let kp_info = match &keys.key_provider {
            KeyProvider::None { .. } => KeyProviderInfo::new("none".into(), "".into()),
            KeyProvider::Local { mr, .. } => {
                KeyProviderInfo::new("local-sgx".into(), hex::encode(mr))
            }
            KeyProvider::Tpm { .. } => {
                bail!("Tpm key provider is not supported");
            }
            KeyProvider::Kms { pubkey, .. } => {
                KeyProviderInfo::new("kms".into(), hex::encode(pubkey))
            }
        };
        emit_key_provider_info(&kp_info)?;
        Ok(())
    }

    async fn setup_fs(self) -> Result<Stage1<'a>> {
        let app_info = self
            .measure_app_info()
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
        safe_write_with_mode(self.app_keys_file(), keys_json, 0o600)
            .context("Failed to write app keys")?;

        // Parse kernel command line options
        let opts = parse_dstack_options(&self.shared).context("Failed to parse kernel cmdline")?;
        emit_runtime_event("storage-fs", opts.storage_fs.to_string().as_bytes())?;
        info!(
            "Filesystem options: encryption={}, filesystem={:?}",
            opts.storage_encrypted, opts.storage_fs
        );

        self.mount_data_disk(&app_keys, &opts).await?;
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
    /// Decrypt the host-supplied env, preferring the sealed format.
    ///
    /// Also returns the env re-sealed to the current epochs when it was
    /// encrypted to older ones, or an empty one when it needs no change.
    async fn decrypt_env(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let current_secret = self.keys.sealed_env_key.as_slice();
        if let Some(sealed_env) = &self.shared.sealed_env {
            let envelope: SealedEnv =
                serde_json::from_slice(sealed_env).context("failed to parse sealed env")?;
            if envelope.version != 1 {
                bail!("unsupported sealed env version: {}", envelope.version);
            }
            if envelope.enc.len() != 32 {
                bail!("sealed env encapsulated key must be 32 bytes");
            }
            let payload = [envelope.enc, envelope.ciphertext].concat();
            let (current_root, current_app) = (self.keys.root_epoch(), self.keys.app_epoch());
            if envelope.root_epoch > current_root || envelope.app_epoch > current_app {
                bail!(
                    "sealed env epoch (root {}, app {}) exceeds current epoch (root {current_root}, app {current_app})",
                    envelope.root_epoch,
                    envelope.app_epoch
                );
            }
            let is_current =
                (envelope.root_epoch, envelope.app_epoch) == (current_root, current_app);
            let historical;
            let secret = if is_current {
                current_secret
            } else {
                historical = self
                    .shared
                    .request_historical_keys(&self.keys, envelope.root_epoch, envelope.app_epoch)
                    .await?;
                historical.sealed_env_key.as_slice()
            };
            let plaintext = crate::crypto::sealed_env_decrypt(
                secret,
                &sealed_env_info_at_epochs(envelope.root_epoch, envelope.app_epoch),
                &payload,
            )?;
            if is_current {
                return Ok((plaintext, Vec::new()));
            }
            let sealed = seal_env_at_epochs(current_secret, current_root, current_app, &plaintext)?;
            return Ok((plaintext, sealed));
        }
        let ciphertext = &self.shared.encrypted_env;
        let current_key = env_crypt_key(&self.keys.env_crypt_key)?;
        let plaintext = match dh_decrypt(current_key, ciphertext) {
            Ok(plaintext) => return Ok((plaintext, Vec::new())),
            Err(_) => {
                let current = self.keys.root_epoch();
                // Legacy encryption is only issued at app epoch zero.
                let epochs = (0..=current)
                    .rev()
                    .filter(|root| *root != current || self.keys.app_epoch() != 0);
                decrypt_historical_env(ciphertext, epochs, async |root| {
                    Ok(self
                        .shared
                        .request_historical_keys(&self.keys, root, 0)
                        .await?
                        .env_crypt_key)
                })
                .await?
            }
        };
        let sealed = seal_env_at_epochs(
            current_secret,
            self.keys.root_epoch(),
            self.keys.app_epoch(),
            &plaintext,
        )?;
        Ok((plaintext, sealed))
    }

    fn write_env_file(&self, env_vars: &BTreeMap<String, String>) -> Result<()> {
        info!("Writing env");
        safe_write_with_mode(
            self.shared.dir.join(DECRYPTED_ENV),
            crate::parse_env_file::convert_env_to_str(env_vars),
            0o600,
        )
        .context("Failed to write decrypted env file")?;
        let env_json = serde_json::to_vec(env_vars).context("Failed to serialize decrypted env")?;
        safe_write_with_mode(self.shared.dir.join(DECRYPTED_ENV_JSON), env_json, 0o600)
            .context("Failed to write decrypted env file")?;
        Ok(())
    }

    async fn unseal_env_vars(&self) -> Result<BTreeMap<String, String>> {
        let allowed_envs: BTreeSet<String> = self
            .shared
            .app_compose
            .allowed_envs
            .iter()
            .cloned()
            .collect();
        let (decrypted_env, sealed) =
            if self.shared.sealed_env.is_none() && self.shared.encrypted_env.is_empty() {
                info!("No encrypted env, using default");
                (Default::default(), Vec::new())
            } else {
                info!("Processing encrypted env");
                let (plaintext, sealed) = self.decrypt_env().await?;
                (
                    crate::parse_env_file::parse_env(&plaintext, &allowed_envs)?,
                    sealed,
                )
            };
        self.write_env_file(&decrypted_env)?;
        // Sent on every boot, empty when nothing changed: it closes the host's
        // env update window, which must be shut before any application code
        // runs, or that code could replace the env the next boot reads.
        close_env_window(
            || self.vmm.update_sealed_env(sealed.clone()),
            &ENV_WINDOW_RETRY_DELAYS,
        )
        .await?;
        Ok(decrypted_env)
    }

    async fn setup(&self) -> Result<()> {
        let _envs = self.unseal_env_vars().await?;
        self.link_files()?;
        self.setup_socket_dir()?;
        self.setup_guest_agent_config()?;
        self.vmm
            .notify_q("boot.progress", "setting up dstack-gateway")
            .await;
        GatewayContext::new(&self.shared, &self.keys)
            .setup(true)
            .await?;
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
                    "pccs_url": self.shared.sys_config.pccs_url,
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

/// Waits between attempts to close the env update window.
const ENV_WINDOW_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

/// Close the host's env update window, retrying `update` after each delay
/// while the host gives no answer. Fails if the window may still be open.
async fn close_env_window<F, Fut>(mut update: F, delays: &[Duration]) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    for delay in delays {
        match update().await {
            Ok(()) => return Ok(()),
            Err(err) => warn!("failed to close the env update window, retrying: {err:#}"),
        }
        tokio::time::sleep(*delay).await;
    }
    update().await.context(
        "the host did not confirm that the env update window is closed; refusing to start applications",
    )
}

async fn decrypt_historical_env<I, F, Fut>(
    ciphertext: &[u8],
    epochs: I,
    mut key_at: F,
) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = u32>,
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    for epoch in epochs {
        let decrypted = key_at(epoch)
            .await
            .and_then(|key| dh_decrypt(env_crypt_key(&key)?, ciphertext));
        match decrypted {
            Ok(plaintext) => return Ok(plaintext),
            Err(err) => warn!("failed to open legacy env at root epoch {epoch}: {err:#}"),
        }
    }
    bail!("failed to decrypt legacy env with accessible historical keys")
}

fn kms_root_epoch(keys: &AppKeys) -> Option<u32> {
    match keys.key_provider {
        KeyProvider::Kms { root_epoch, .. } => Some(root_epoch),
        _ => None,
    }
}

#[test]
fn wireguard_fields_reject_config_syntax() {
    for endpoint in [
        "gateway.example.com:51820",
        "192.0.2.1:51821",
        "[2001:db8::1]:51822",
    ] {
        assert_eq!(validate_wg_endpoint(endpoint).unwrap(), endpoint);
    }
    for endpoint in [
        "",
        "192.0.2.1",
        "192.0.2.1:99999",
        "0.0.0.0/0:1",
        "192.0.2.1:51820\n[Interface]\nPostUp = id",
        "[not-v6]:51820",
    ] {
        assert!(validate_wg_endpoint(endpoint).is_err(), "{endpoint:?}");
    }

    let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert_eq!(parse_wg_public_key(key).unwrap(), key);
    assert!(parse_wg_public_key(&format!("{key}\nPostUp = id")).is_err());
    assert!(parse_wg_public_key("AAAA").is_err());

    assert!(parse_wg_ip("10.0.0.2").is_ok());
    assert!(parse_wg_ip("10.0.0.2/32\n[Interface]").is_err());
}

#[cfg(test)]
mod sealed_env_file_tests {
    use super::*;

    fn stage(args: &SetupArgs, sealed_env: Option<Vec<u8>>, encrypted_env: Vec<u8>) -> Stage1<'_> {
        Stage1 {
            args,
            vmm: HostApi::default(),
            shared: HostShared {
                dir: HostShareDir::new(&args.work_dir),
                sys_config: serde_json::from_value(serde_json::json!({"vm_config": ""})).unwrap(),
                app_compose: serde_json::from_value(serde_json::json!({
                    "manifest_version": 2, "name": "sealed-test", "runner": "docker-compose"
                }))
                .unwrap(),
                instance_info: InstanceInfo::default(),
                sealed_env,
                encrypted_env,
            },
            keys: AppKeys {
                disk_crypt_key: vec![],
                env_crypt_key: vec![9; 32],
                sealed_env_key: vec![7; 32],
                k256_key: vec![],
                k256_signature: vec![],
                gateway_app_id: String::new(),
                ca_cert: String::new(),
                key_provider: KeyProvider::Kms {
                    url: "http://127.0.0.1:1".into(),
                    pubkey: vec![],
                    tmp_ca_key: String::new(),
                    tmp_ca_cert: String::new(),
                    root_epoch: 3,
                    app_epoch: 0,
                },
            },
        }
    }

    #[tokio::test]
    async fn guest_preserves_env_at_the_current_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let args = SetupArgs {
            work_dir: dir.path().into(),
            device: "unused".into(),
            mount_point: "unused".into(),
        };
        let plaintext = br#"{"env":[{"key":"MESSAGE","value":"test"}]}"#;
        let sealed = seal_env(&[7; 32], 3, plaintext).unwrap();
        let current = stage(&args, Some(sealed), b"invalid legacy".to_vec());
        let (opened, update) = current.decrypt_env().await.unwrap();
        assert_eq!(opened, plaintext);
        assert!(update.is_empty());

        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([9; 32]));
        let legacy = crate::crypto::dh_encrypt(public.to_bytes(), plaintext).unwrap();
        let old = stage(&args, None, legacy.clone());
        let (opened, update) = old.decrypt_env().await.unwrap();
        assert_eq!(opened, plaintext);
        assert!(update.is_empty());
        let mut without_sealed_key = stage(&args, None, legacy.clone());
        without_sealed_key.keys.sealed_env_key.clear();
        let (opened, update) = without_sealed_key.decrypt_env().await.unwrap();
        assert_eq!(opened, plaintext);
        assert!(update.is_empty());

        for invalid in [
            Vec::new(),
            b"invalid JSON".to_vec(),
            br#"{"version":2,"root_epoch":3,"enc":"","ciphertext":""}"#.to_vec(),
        ] {
            assert!(stage(&args, Some(invalid), legacy.clone())
                .decrypt_env()
                .await
                .is_err());
        }
        let future = seal_env(&[7; 32], 4, plaintext).unwrap();
        assert!(stage(&args, Some(future), legacy)
            .decrypt_env()
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds current"));
    }

    /// Run `close_env_window` against `answers`, returning its result and how
    /// often the host was asked.
    async fn close_with(answers: Vec<Result<()>>) -> (Result<()>, usize) {
        let mut answers = answers.into_iter();
        let mut calls = 0;
        let result = close_env_window(
            || {
                calls += 1;
                std::future::ready(answers.next().unwrap())
            },
            &[Duration::ZERO; 2],
        )
        .await;
        (result, calls)
    }

    #[tokio::test]
    async fn applications_start_only_once_the_env_window_is_closed() {
        let (result, calls) = close_with(vec![Ok(())]).await;
        result.unwrap();
        assert_eq!(calls, 1);
        // A lost answer is retried.
        let (result, calls) = close_with(vec![Err(anyhow!("connection reset")), Ok(())]).await;
        result.unwrap();
        assert_eq!(calls, 2);
        // No answer within the retries fails the boot.
        let (result, calls) = close_with(vec![
            Err(anyhow!("timed out")),
            Err(anyhow!("timed out")),
            Err(anyhow!("connection refused")),
        ])
        .await;
        let err = format!("{:#}", result.unwrap_err());
        assert!(err.contains("refusing to start applications"), "{err}");
        assert!(err.contains("connection refused"), "{err}");
        assert_eq!(calls, 3);
    }

    #[tokio::test]
    async fn legacy_env_migration_skips_denied_intermediate_epochs() {
        let secret = x25519_dalek::StaticSecret::from([8; 32]);
        let public = x25519_dalek::PublicKey::from(&secret);
        let plaintext = br#"{"env":[{"key":"SECRET","value":"synthetic"}]}"#;
        let encrypted = crate::crypto::dh_encrypt(public.to_bytes(), plaintext).unwrap();
        let mut requested = Vec::new();
        let decrypted = decrypt_historical_env(&encrypted, (0..2).rev(), |epoch| {
            requested.push(epoch);
            std::future::ready(if epoch == 0 {
                Ok(secret.to_bytes().to_vec())
            } else {
                Err(anyhow::anyhow!("authorization denied"))
            })
        })
        .await
        .unwrap();
        assert_eq!(requested, [1, 0]);
        assert_eq!(decrypted, plaintext);
        assert!(
            decrypt_historical_env(&encrypted, (0..2).rev(), |_| async { bail!("denied") })
                .await
                .is_err()
        );
        assert!(
            decrypt_historical_env(&encrypted, (0..2).rev(), |_| async { Ok(vec![3; 32]) })
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn sealed_env_at_the_current_epochs_opens_and_binds_both_epochs() {
        let dir = tempfile::tempdir().unwrap();
        let args = SetupArgs {
            work_dir: dir.path().into(),
            device: "unused".into(),
            mount_point: "unused".into(),
        };
        let plaintext = br#"{"env":[{"key":"VALUE","value":"epoch-test"}]}"#;
        let sealed = seal_env_at_epochs(&[7; 32], 3, 2, plaintext).unwrap();
        let mut current = stage(&args, Some(sealed.clone()), vec![]);
        if let KeyProvider::Kms { app_epoch, .. } = &mut current.keys.key_provider {
            *app_epoch = 2;
        }
        let (opened, update) = current.decrypt_env().await.unwrap();
        assert_eq!(opened, plaintext);
        assert!(update.is_empty());
        let mut tampered: Value = serde_json::from_slice(&sealed).unwrap();
        tampered["version"] = 2.into();
        current.shared.sealed_env = Some(serde_json::to_vec(&tampered).unwrap());
        let err = current.decrypt_env().await.unwrap_err();
        assert!(
            err.to_string().contains("unsupported sealed env version"),
            "{err}"
        );
        let envelope: SealedEnv = serde_json::from_slice(&sealed).unwrap();
        assert_eq!(envelope.version, 1);
        let payload = [envelope.enc.clone(), envelope.ciphertext.clone()].concat();
        assert!(crate::crypto::sealed_env_decrypt(
            &[7; 32],
            &sealed_env_info_at_epochs(3, 1),
            &payload
        )
        .is_err());
        assert!(crate::crypto::sealed_env_decrypt(
            &[7; 32],
            &sealed_env_info_at_epochs(2, 2),
            &payload
        )
        .is_err());
    }

    #[test]
    fn sealed_file_selection_ignores_legacy_but_rejects_links() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(SYS_CONFIG), br#"{"vm_config":""}"#).unwrap();
        fs::write(
            dir.path().join(APP_COMPOSE),
            br#"{"manifest_version":2,"name":"test","runner":"docker-compose"}"#,
        )
        .unwrap();
        let sealed_path = dir.path().join(SEALED_ENV);
        fs::write(&sealed_path, b"sealed bytes").unwrap();
        fs::create_dir(dir.path().join(ENCRYPTED_ENV)).unwrap();
        let shared = HostShared::load(dir.path()).unwrap();
        assert_eq!(shared.sealed_env.unwrap(), b"sealed bytes");
        assert!(shared.encrypted_env.is_empty());
        fs::remove_file(&sealed_path).unwrap();
        std::os::unix::fs::symlink("missing-target", &sealed_path).unwrap();
        assert!(env_file_exists(&sealed_path).is_err());
        assert!(HostShared::load(dir.path()).is_err());
    }

    #[test]
    fn missing_empty_and_unreadable_env_are_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SEALED_ENV);
        assert_eq!(read_optional_env(&path).unwrap(), None);
        fs::write(&path, []).unwrap();
        assert_eq!(read_optional_env(&path).unwrap(), Some(Vec::new()));
        assert!(
            serde_json::from_slice::<SealedEnv>(&read_optional_env(&path).unwrap().unwrap())
                .is_err()
        );
        assert!(read_optional_env(dir.path()).is_err());
    }
}
