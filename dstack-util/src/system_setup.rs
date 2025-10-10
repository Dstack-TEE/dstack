// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    ops::Deref,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use dstack_kms_rpc as rpc;
use dstack_types::{
    shared_filenames::{
        APP_COMPOSE, APP_KEYS, DECRYPTED_ENV, DECRYPTED_ENV_JSON, ENCRYPTED_ENV,
        HOST_SHARED_DIR_NAME, INSTANCE_INFO, SYS_CONFIG, USER_CONFIG,
    },
    KeyProvider, KeyProviderInfo,
};
use fs_err as fs;
use luks2::{
    LuksAf, LuksConfig, LuksDigest, LuksHeader, LuksJson, LuksKdf, LuksKeyslot, LuksSegment,
    LuksSegmentSize,
};
use ra_rpc::client::{CertInfo, RaClient, RaClientConfig};
use ra_tls::cert::generate_ra_cert;
use rand::Rng as _;
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use tdx_attest::extend_rtmr3;
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
    gateway_client::GatewayClient, RegisterCvmRequest, RegisterCvmResponse, WireGuardPeer,
};
use ra_tls::{
    cert::CertConfig,
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
use serde_human_bytes as hex_bytes;
use serde_json::Value;

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
    Xfs,
}

impl Display for FsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsType::Zfs => write!(f, "zfs"),
            FsType::Ext4 => write!(f, "ext4"),
            FsType::Xfs => write!(f, "xfs"),
        }
    }
}

impl FromStr for FsType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "zfs" => Ok(FsType::Zfs),
            "ext4" => Ok(FsType::Ext4),
            "xfs" => Ok(FsType::Xfs),
            _ => bail!("Invalid filesystem type: {s}, supported types: zfs, ext4, xfs"),
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

impl InstanceInfo {
    fn is_initialized(&self) -> bool {
        !self.instance_id_seed.is_empty()
    }
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
        cmd! {
            info "Mounting host-shared";
            mkdir -p $host_shared_dir;
            mount -t 9p -o trans=virtio,version=9p2000.L,ro host-shared $host_shared_dir;
            mkdir -p $host_shared_copy_dir;
            info "Copying host-shared files";
        }?;
        copy(APP_COMPOSE, SZ_1KB * 256, false)?;
        copy(SYS_CONFIG, SZ_1KB * 32, false)?;
        copy(INSTANCE_INFO, SZ_1KB * 10, true)?;
        copy(ENCRYPTED_ENV, SZ_1KB * 256, true)?;
        copy(USER_CONFIG, SZ_1MB, true)?;
        cmd! {
            info "Unmounting host-shared";
            umount $host_shared_dir;
        }?;
        HostShared::load(host_shared_copy_dir)
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

    async fn register_cvm(
        &self,
        gateway_url: &str,
        client_key: String,
        client_cert: String,
        wg_pk: String,
    ) -> Result<RegisterCvmResponse> {
        let url = format!("{}/prpc", gateway_url);
        let ca_cert = self.keys.ca_cert.clone();
        let cert_validator = AppIdValidator {
            allowed_app_id: self.keys.gateway_app_id.clone(),
        };
        let client = RaClientConfig::builder()
            .remote_uri(url)
            .maybe_pccs_url(self.shared.sys_config.pccs_url.clone())
            .tls_client_cert(client_cert)
            .tls_client_key(client_key)
            .tls_ca_cert(ca_cert)
            .tls_built_in_root_certs(false)
            .tls_no_check(self.keys.gateway_app_id == "any")
            .verify_server_attestation(false)
            .cert_validator(Box::new(move |cert| cert_validator.validate(cert)))
            .build()
            .into_client()
            .context("Failed to create RA client")?;
        let client = GatewayClient::new(client);
        client
            .register_cvm(RegisterCvmRequest {
                client_public_key: wg_pk,
            })
            .await
            .context("Failed to register CVM")
    }

    async fn setup(&self) -> Result<()> {
        if !self.shared.app_compose.gateway_enabled() {
            info!("dstack-gateway is not enabled");
            return Ok(());
        }
        if self.keys.gateway_app_id.is_empty() {
            bail!("Missing allowed dstack-gateway app id");
        }

        info!("Setting up dstack-gateway");
        // Generate WireGuard keys
        let sk = cmd!(wg genkey)?;
        let pk = cmd!(echo $sk | wg pubkey).or(Err(anyhow!("Failed to generate public key")))?;

        let config = CertConfig {
            org_name: None,
            subject: "dstack-guest-agent".to_string(),
            subject_alt_names: vec![],
            usage_server_auth: false,
            usage_client_auth: true,
            ext_quote: true,
        };
        let cert_client = CertRequestClient::create(
            self.keys,
            self.shared.sys_config.pccs_url.as_deref(),
            self.shared.sys_config.vm_config.clone(),
        )
        .await
        .context("Failed to create cert client")?;
        let client_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("Failed to generate key")?;
        let client_certs = cert_client
            .request_cert(&client_key, config, false)
            .await
            .context("Failed to request cert")?;
        let client_cert = client_certs.join("\n");
        let client_key = client_key.serialize_pem();

        if self.shared.sys_config.gateway_urls.is_empty() {
            bail!("Missing gateway urls");
        }
        // Read config and make API call
        let response = 'out: {
            for url in self.shared.sys_config.gateway_urls.iter() {
                let response = self
                    .register_cvm(url, client_key.clone(), client_cert.clone(), pk.clone())
                    .await;
                match response {
                    Ok(response) => {
                        break 'out response;
                    }
                    Err(err) => {
                        warn!("Failed to register CVM: {err:?}, retrying with next dstack-gateway");
                    }
                }
            }
            bail!("Failed to register CVM, all dstack-gateway urls are down");
        };
        let wg_info = response.wg.context("Missing wg info")?;

        let client_ip = &wg_info.client_ip;

        // Create WireGuard config
        let wg_listen_port = "9182";
        let mut config = format!(
            "[Interface]\n\
            PrivateKey = {sk}\n\
            ListenPort = {wg_listen_port}\n\
            Address = {client_ip}/32\n\n"
        );
        for WireGuardPeer { pk, ip, endpoint } in &wg_info.servers {
            let ip = ip.split('/').next().unwrap_or_default();
            config.push_str(&format!(
                "[Peer]\n\
                PublicKey = {pk}\n\
                AllowedIPs = {ip}/32\n\
                Endpoint = {endpoint}\n\
                PersistentKeepalive = 25\n",
            ));
        }

        let wg_dir = Path::new("/etc/wireguard");
        fs::create_dir_all(wg_dir)?;
        fs::write(wg_dir.join("dstack-wg0.conf"), config)?;

        cmd! {
            chmod 600 $wg_dir/dstack-wg0.conf;
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
    extend_rtmr3("key-provider", &provider_info_json)?;
    Ok(())
}

pub async fn cmd_sys_setup(args: SetupArgs) -> Result<()> {
    let stage0 = Stage0::load(&args)?;
    if stage0.shared.app_compose.secure_time {
        info!("Waiting for the system time to be synchronized");
        cmd! {
            chronyc waitsync 20 0.1;
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

    GatewayContext::new(&shared, &keys).setup().await
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
        let ra_client = RaClientConfig::builder()
            .tls_no_check(false)
            .tls_built_in_root_certs(false)
            .remote_uri(kms_url.clone())
            .tls_client_cert(cert_pair.cert_pem)
            .tls_client_key(cert_pair.key_pem)
            .tls_ca_cert(tmp_ca.ca_cert.clone())
            .maybe_pccs_url(self.shared.sys_config.pccs_url.clone())
            .cert_validator(Box::new(|cert| {
                let Some(cert) = cert else {
                    bail!("Missing server cert");
                };
                let Some(usage) = cert.special_usage else {
                    bail!("Missing server cert usage");
                };
                if usage != "kms:rpc" {
                    bail!("Invalid server cert usage: {usage}");
                }
                if let Some(att) = &cert.attestation {
                    let kms_info = att
                        .decode_app_info(false)
                        .context("Failed to decode app_info")?;
                    extend_rtmr3("mr-kms", &kms_info.mr_aggregated)
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
                vm_config: self.shared.sys_config.vm_config.clone(),
            })
            .await
            .context("Failed to get app key")?;

        extend_rtmr3("os-image-hash", &response.os_image_hash)
            .context("Failed to extend os-image-hash to RTMR3")?;

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
            for kms_url in self.shared.sys_config.kms_urls.iter() {
                let kms_url = format!("{kms_url}/prpc");
                let response = self.request_app_keys_from_kms_url(kms_url.clone()).await;
                match response {
                    Ok(response) => {
                        break 'out response;
                    }
                    Err(err) => {
                        warn!("Failed to get app keys from KMS {kms_url}: {err:?}");
                    }
                }
            }
            bail!("Failed to get app keys from KMS");
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
        let app_keys = gen_app_keys_from_seed(&provision.sk, Some(provision.mr.to_vec()))
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
                gen_app_keys_from_seed(&seed, None).context("Failed to generate app keys")
            }
        }
    }

    async fn setup_swap(&self, swap_size: u64, opts: &DstackOptions) -> Result<()> {
        match opts.storage_fs {
            FsType::Zfs => self.setup_swap_zvol(swap_size).await,
            FsType::Ext4 | FsType::Xfs => self.setup_swapfile(swap_size).await,
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

    async fn mount_data_disk(
        &self,
        initialized: bool,
        disk_crypt_key: &str,
        opts: &DstackOptions,
    ) -> Result<()> {
        let name = "dstack_data_disk";
        let mount_point = &self.args.mount_point;

        // Determine the device to use based on encryption settings
        let fs_dev = if opts.storage_encrypted {
            format!("/dev/mapper/{name}")
        } else {
            self.args.device.to_string_lossy().to_string()
        };

        cmd!(mkdir -p $mount_point).context("Failed to create mount point")?;

        if !initialized {
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
                FsType::Xfs => {
                    info!("Creating xfs filesystem");
                    cmd! {
                        mkfs.xfs -f $fs_dev;
                    }
                    .context("Failed to create xfs filesystem")?;
                    Self::mount_xfs(&fs_dev, mount_point, false)
                        .context("Failed to mount newly created xfs filesystem")?;
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
                FsType::Xfs => {
                    Self::mount_xfs(&fs_dev, mount_point, true)
                        .context("Failed to mount xfs filesystem")?;
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

    fn mount_xfs(
        dev: &impl AsRef<Path>,
        mount_point: &impl AsRef<Path>,
        run_check: bool,
    ) -> Result<()> {
        let dev = dev.as_ref();
        let mount_point = mount_point.as_ref();
        if run_check {
            info!("Checking filesystem");

            let repair_status = Command::new("xfs_repair")
                .arg("-n")
                .arg(dev)
                .status()
                .with_context(|| format!("Failed to run xfs_repair on {}", dev.display()))?;

            match repair_status.code() {
                Some(0) => {}
                Some(1) => {
                    warn!(
                        "xfs_repair reported issues on {}, continuing without modification",
                        dev.display()
                    );
                }
                Some(code) => {
                    bail!(
                        "xfs_repair exited with status {code} while checking {}",
                        dev.display()
                    );
                }
                None => {
                    bail!(
                        "xfs_repair terminated by signal while checking {}",
                        dev.display()
                    );
                }
            }
        }

        cmd! {
            info "Mounting filesystem";
            mount $dev $mount_point;
        }
        .context("Failed to mount xfs filesystem")?;

        cmd! {
            info "Growing filesystem if needed";
            xfs_growfs $mount_point;
        }
        .context("Failed to grow xfs filesystem")?;

        Ok(())
    }

    fn luks_setup(&self, disk_crypt_key: &str, name: &str) -> Result<()> {
        let root_hd = &self.args.device;
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

        cmd! {
            info "Opening the device";
            echo -n $disk_crypt_key | cryptsetup luksOpen --type luks2 --header $in_mem_hdr -d- $root_hd $name;
        }
        .or(Err(anyhow!("Failed to open encrypted data disk")))?;
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
        if !kms_enabled && instance_info.app_id != truncated_compose_hash {
            bail!("App upgrade is not supported without KMS");
        }

        extend_rtmr3("system-preparing", &[])?;
        extend_rtmr3("app-id", &instance_info.app_id)?;
        extend_rtmr3("compose-hash", &compose_hash)?;
        extend_rtmr3("instance-id", &instance_id)?;
        extend_rtmr3("boot-mr-done", &[])?;
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
            KeyProvider::Kms { pubkey, .. } => {
                KeyProviderInfo::new("kms".into(), hex::encode(pubkey))
            }
        };
        emit_key_provider_info(&kp_info)?;
        Ok(())
    }

    async fn setup_fs(self) -> Result<Stage1<'a>> {
        let is_initialized = self.shared.instance_info.is_initialized();
        let app_info = self
            .measure_app_info()
            .context("Failed to measure app info")?;
        if self.shared.app_compose.key_provider().is_kms() {
            cmd_show_mrs()?;
        }
        self.vmm
            .notify_q("boot.progress", "requesting app keys")
            .await;
        let app_keys = self.request_app_keys().await?;
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
        extend_rtmr3("storage-fs", opts.storage_fs.to_string().as_bytes())?;
        info!(
            "Filesystem options: encryption={}, filesystem={:?}",
            opts.storage_encrypted, opts.storage_fs
        );

        self.mount_data_disk(
            is_initialized,
            &hex::encode(&app_keys.disk_crypt_key),
            &opts,
        )
        .await?;
        self.setup_swap(self.shared.app_compose.swap_size, &opts)
            .await?;
        self.vmm
            .notify_q(
                "instance.info",
                &serde_json::to_string(&app_info.instance_info)?,
            )
            .await;
        extend_rtmr3("system-ready", &[])?;
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
        let envs = self.unseal_env_vars()?;
        self.link_files()?;
        self.setup_guest_agent_config()?;
        self.vmm
            .notify_q("boot.progress", "setting up dstack-gateway")
            .await;
        GatewayContext::new(&self.shared, &self.keys)
            .setup()
            .await?;
        self.vmm
            .notify_q("boot.progress", "setting up docker")
            .await;
        self.setup_docker_registry()?;
        self.setup_docker_account(&envs)?;
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
            .app_compose
            .docker_config
            .registry
            .as_deref()
            .unwrap_or_default();
        let registry_url = if registry_url.is_empty() {
            self.shared
                .sys_config
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

    fn setup_docker_account(&self, envs: &BTreeMap<String, String>) -> Result<()> {
        info!("Setting up docker account");
        let username = self
            .shared
            .app_compose
            .docker_config
            .username
            .as_deref()
            .unwrap_or_default();
        if username.is_empty() {
            return Ok(());
        }
        let token_key = self
            .shared
            .app_compose
            .docker_config
            .token_key
            .as_deref()
            .unwrap_or_default();
        if token_key.is_empty() {
            return Ok(());
        }
        let token = envs
            .get(token_key)
            .with_context(|| format!("Missing token for {username}"))?;
        if token.is_empty() {
            bail!("Missing token for {username}");
        }
        cmd!(docker login -u $username -p $token)?;
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
