use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use dstack_types::{
    shared_filenames::{
        APP_COMPOSE, APP_KEYS, DECRYPTED_ENV, DECRYPTED_ENV_JSON, ENCRYPTED_ENV, INSTANCE_INFO,
        SYS_CONFIG, USER_CONFIG,
    },
    KeyProvider, KeyProviderInfo,
};
use fs_err as fs;
use kms_rpc::GetAppKeyRequest;
use ra_rpc::client::{RaClient, RaClientConfig};
use ra_tls::cert::generate_ra_cert;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    cmd_gen_app_keys, cmd_show_mrs,
    crypto::dh_decrypt,
    gen_app_keys_from_seed,
    host_api::HostApi,
    utils::{
        deserialize_json_file, extend_rtmr3, sha256, sha256_file, AppCompose, AppKeys, HashingFile,
        KeyProviderKind, SysConfig,
    },
    GenAppKeysArgs,
};
use cmd_lib::run_cmd as cmd;
use serde_human_bytes as hex_bytes;

mod env_process;

// Workaround for clap mis-infer the arg type according the type name
type Bool = bool;
type Bytes = Vec<u8>;

#[derive(clap::Parser)]
/// Prepare full disk encryption
pub struct SetupFdeArgs {
    /// Host shared directory
    #[arg(long)]
    host_shared: PathBuf,
    /// Copied host-shared directory
    #[arg(long, default_value = "/tapp/.host-shared")]
    host_shared_copy: PathBuf,
    /// Working directory
    #[arg(long)]
    work_dir: PathBuf,
    /// Root fs mount point
    #[arg(long)]
    rootfs_dir: PathBuf,
    /// Root hard disk device
    #[arg(long)]
    root_hd: String,
    /// Root fs cdrom device
    #[arg(long)]
    root_cdrom: String,
    /// Root fs cdrom mount point
    #[arg(long)]
    root_cdrom_mnt: PathBuf,
    /// Enabled rootfs integrity
    #[arg(long)]
    rootfs_integrity: bool,
    /// Enabled rootfs encryption
    #[arg(long, default_value_t = true)]
    rootfs_encryption: Bool,
    /// Rootfs hash
    #[arg(long, value_parser = parse_hex_bytes)]
    rootfs_hash: Bytes,
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(s).context("Failed to decode hex string")?;
    Ok(bytes)
}

#[derive(Deserialize, Serialize, Clone, Default)]
struct InstanceInfo {
    #[serde(default)]
    bootstrapped: Option<bool>,
    #[serde(with = "hex_bytes", default)]
    instance_id_seed: Vec<u8>,
    #[serde(with = "hex_bytes", default)]
    instance_id: Vec<u8>,
    #[serde(with = "hex_bytes", default)]
    app_id: Vec<u8>,
}

impl InstanceInfo {
    fn is_bootstrapped(&self) -> bool {
        self.bootstrapped
            .unwrap_or(!self.instance_id_seed.is_empty())
    }
}

#[derive(Clone)]
pub struct HostShareDir {
    base_dir: PathBuf,
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
    vm_config: SysConfig,
    app_compose: AppCompose,
    encrypted_env: Vec<u8>,
    instance_info: InstanceInfo,
}

impl HostShared {
    fn load(host_shared_dir: impl Into<HostShareDir>) -> Result<Self> {
        let host_shared_dir = host_shared_dir.into();
        let vm_config = deserialize_json_file(host_shared_dir.sys_config_file())?;
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
            vm_config,
            app_compose,
            encrypted_env,
            instance_info,
        })
    }
}

fn truncate(s: &[u8], len: usize) -> &[u8] {
    if s.len() > len {
        &s[..len]
    } else {
        s
    }
}

impl SetupFdeArgs {
    fn app_keys_file(&self) -> PathBuf {
        self.host_shared_copy.join(APP_KEYS)
    }

    fn copy_host_shared(&self) -> Result<HostShared> {
        let host_shared_dir = &self.host_shared;
        let host_shared_copy_dir = &self.host_shared_copy;

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
            std::fs::copy(src_path, dst_path)?;
            Ok(())
        };
        cmd! {
            info "Mounting host-shared";
            mkdir -p $host_shared_dir;
            mount -t 9p -o trans=virtio,version=9p2000.L,ro host-shared $host_shared_dir;
            mkdir -p $host_shared_copy_dir/;
            info "Copying host-shared files";
        }?;
        copy(APP_COMPOSE, SZ_1KB * 128, false)?;
        copy(SYS_CONFIG, SZ_1KB * 10, false)?;
        copy(INSTANCE_INFO, SZ_1KB * 10, true)?;
        copy(ENCRYPTED_ENV, SZ_1KB * 256, true)?;
        copy(USER_CONFIG, SZ_1MB, true)?;
        cmd! {
            info "Unmounting host-shared";
            umount $host_shared_dir;
        }?;
        HostShared::load(host_shared_copy_dir.as_path())
    }

    async fn request_app_keys_from_kms_url(
        &self,
        kms_url: String,
        app_compose: String,
    ) -> Result<AppKeys> {
        info!("Requesting app keys from KMS: {kms_url}");

        let tmp_ca = {
            info!("Getting temp ca cert");
            let client = RaClient::new(kms_url.clone(), true)?;
            let kms_client = kms_rpc::kms_client::KmsClient::new(client);
            kms_client
                .get_temp_ca_cert()
                .await
                .context("Failed to get temp ca cert")?
        };
        let cert_pair = generate_ra_cert(tmp_ca.temp_ca_cert, tmp_ca.temp_ca_key)?;
        let ra_client = RaClientConfig::builder()
            .tls_no_check(false)
            .tls_built_in_root_certs(false)
            .remote_uri(kms_url.clone())
            .tls_client_cert(cert_pair.cert_pem)
            .tls_client_key(cert_pair.key_pem)
            .tls_ca_cert(tmp_ca.ca_cert.clone())
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
                Ok(())
            }))
            .build()
            .into_client()
            .context("Failed to create client")?;
        let kms_client = kms_rpc::kms_client::KmsClient::new(ra_client);
        let response = kms_client
            .get_app_key(GetAppKeyRequest { app_compose })
            .await
            .context("Failed to get app key")?;
        let keys = AppKeys {
            ca_cert: tmp_ca.ca_cert,
            disk_crypt_key: response.disk_crypt_key,
            env_crypt_key: response.env_crypt_key,
            k256_key: response.k256_key,
            k256_signature: response.k256_signature,
            tproxy_app_id: response.tproxy_app_id,
            key_provider: KeyProvider::Kms { url: kms_url },
        };
        Ok(keys)
    }

    async fn request_app_keys_from_kms(&self, host_shared: &HostShared) -> Result<()> {
        if host_shared.vm_config.kms_urls.is_empty() {
            bail!("No KMS URLs are set");
        }
        let gen_certs_dir = self.work_dir.join("certs");
        fs::create_dir_all(&gen_certs_dir).context("Failed to create certs dir")?;
        let app_compose = fs::read_to_string(host_shared.dir.app_compose_file())
            .context("Failed to read app compose file")?;
        let keys = 'out: {
            for kms_url in host_shared.vm_config.kms_urls.iter() {
                let kms_url = format!("{kms_url}/prpc");
                let response = self
                    .request_app_keys_from_kms_url(kms_url.clone(), app_compose.clone())
                    .await;
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
        {
            let (_, ca_pem) = x509_parser::pem::parse_x509_pem(keys.ca_cert.as_bytes())
                .context("Failed to parse ca cert")?;
            let x509 = ca_pem.parse_x509().context("Failed to parse ca cert")?;
            let id = hex::encode(x509.public_key().raw);
            let provider_info = KeyProviderInfo::new("kms".into(), id);
            emit_key_provider_info(&provider_info)?;
        };
        let keys_json = serde_json::to_string(&keys).context("Failed to serialize app keys")?;
        fs::write(self.app_keys_file(), keys_json).context("Failed to write app keys")?;
        Ok(())
    }

    async fn get_keys_from_local_key_provider(&self, host: &HostApi) -> Result<()> {
        info!("Getting keys from local key provider");
        let provision = host
            .get_sealing_key()
            .await
            .context("Failed to get sealing key")?;
        // write to fs
        let app_keys =
            gen_app_keys_from_seed(&provision.sk).context("Failed to generate app keys")?;
        let keys_json = serde_json::to_string(&app_keys).context("Failed to serialize app keys")?;
        fs::write(self.app_keys_file(), keys_json).context("Failed to write app keys")?;

        // write to RTMR
        let provider_info = KeyProviderInfo::new("local-sgx".into(), hex::encode(provision.mr));
        emit_key_provider_info(&provider_info)?;
        Ok(())
    }

    async fn request_app_keys(&self, host_shared: &HostShared, host: &HostApi) -> Result<AppKeys> {
        let key_provider = host_shared.app_compose.key_provider();
        match key_provider {
            KeyProviderKind::Kms => self.request_app_keys_from_kms(host_shared).await?,
            KeyProviderKind::Local => self.get_keys_from_local_key_provider(host).await?,
            KeyProviderKind::None => {
                info!("No key provider is enabled, generating temporary app keys");
                let provider_info = KeyProviderInfo::new("none".into(), "".into());
                emit_key_provider_info(&provider_info)?;
                cmd_gen_app_keys(GenAppKeysArgs {
                    ca_level: 1,
                    output: self.app_keys_file(),
                })?;
            }
        }

        deserialize_json_file(self.app_keys_file()).context("Failed to decode app keys")
    }

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
            env_process::parse_env(&decrypted_json, allowed)?
        } else {
            info!("No encrypted env, using default");
            Default::default()
        };
        Ok(vars)
    }

    fn mount_e2fs(dev: &str, mount_point: &Path) -> Result<()> {
        cmd! {
            info "Checking filesystem";
            sh -c "e2fsck -f -p $dev || [ $? -le 2 ]";
            info "Trying to resize filesystem if needed";
            resize2fs $dev;
            info "Mounting filesystem";
            mount $dev $mount_point;
        }?;
        Ok(())
    }

    async fn mount_rootfs(&self, disk_crypt_key: &str, host: &HostApi) -> Result<()> {
        let rootfs_mountpoint = &self.rootfs_dir;
        let rootfs_dev = if self.rootfs_encryption {
            info!("Mounting encrypted rootfs");
            let root_hd = &self.root_hd;
            let disk_crypt_key = disk_crypt_key.trim();
            cmd!(echo -n $disk_crypt_key | cryptsetup luksOpen --type luks2 -d- $root_hd rootfs_crypt)
                .or(Err(anyhow!("Failed to open encrypted rootfs")))?;
            "/dev/mapper/rootfs_crypt"
        } else {
            warn!("Rootfs encryption is disabled, skipping disk encryption");
            &self.root_hd
        };
        Self::mount_e2fs(rootfs_dev, rootfs_mountpoint)?;

        let hash_file = self.rootfs_dir.join(".rootfs_hash");
        let existing_rootfs_hash = fs::read(&hash_file).unwrap_or_default();
        if existing_rootfs_hash != self.rootfs_hash {
            info!("Rootfs hash changed, upgrading the rootfs");
            let upgrading_file = self.rootfs_dir.join(".rootfs_upgrading");
            if upgrading_file.exists() {
                bail!("The previous rootfs upgrade is not finished, aborting");
            }
            fs::write(&upgrading_file, "").context("Failed to touch upgrading file")?;
            if hash_file.exists() {
                fs::remove_file(&hash_file).context("Failed to remove old rootfs hash file")?;
            }
            host.notify_q("boot.progress", "upgrading rootfs").await;
            self.extract_rootfs(&self.rootfs_hash).await?;
            fs::remove_file(&upgrading_file).context("Failed to remove upgrading file")?;
        }
        Ok(())
    }

    fn luks_setup(&self, disk_crypt_key: &str) -> Result<()> {
        let opts = if self.rootfs_integrity {
            vec!["--integrity", "hmac-sha256"]
        } else {
            vec![]
        };
        let root_hd = &self.root_hd;
        cmd! {
            info "Formatting encrypted rootfs";
            echo -n $disk_crypt_key |
                cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --pbkdf pbkdf2 -d- $[opts] $root_hd rootfs_crypt;

            info "Opening the device";
            echo -n $disk_crypt_key |
                cryptsetup luksOpen --type luks2 -d- $root_hd rootfs_crypt;
        }.or(Err(anyhow!("Failed to setup luks volume")))?;
        Ok(())
    }

    async fn bootstrap_rootfs(
        &self,
        disk_crypt_key: &str,
        instance_info: &InstanceInfo,
        host: &HostApi,
    ) -> Result<()> {
        info!("Setting up disk encryption");
        info!("Formatting rootfs");
        let rootfs_dev = if self.rootfs_encryption {
            self.luks_setup(disk_crypt_key)?;
            "/dev/mapper/rootfs_crypt"
        } else {
            warn!("Rootfs encryption is disabled, skipping disk encryption");
            &self.root_hd
        };
        let rootfs_dir = &self.rootfs_dir;
        cmd!(mkfs.ext4 -L dstack-rootfs $rootfs_dev)?;
        cmd!(mount $rootfs_dev $rootfs_dir)?;

        self.extract_rootfs(&self.rootfs_hash).await?;
        host.notify_q("instance.info", &serde_json::to_string(instance_info)?)
            .await;
        Ok(())
    }

    async fn extract_rootfs(&self, expected_rootfs_hash: &[u8]) -> Result<()> {
        info!("Extracting rootfs");
        fs::create_dir_all(&self.root_cdrom_mnt)
            .context("Failed to create rootfs cdrom mount point")?;

        let cdrom_device = &self.root_cdrom;
        let cdrom_mnt = &self.root_cdrom_mnt;
        cmd!(mount -t iso9660 -o ro $cdrom_device $cdrom_mnt)?;

        let rootfs_cpio = cdrom_mnt.join("rootfs.cpio");
        if !rootfs_cpio.exists() {
            bail!("Rootfs cpio file not found on cdrom");
        }
        let rootfs_cpio_file =
            fs::File::open(rootfs_cpio).context("Failed to open rootfs cpio file")?;
        let mut hashing_rootfs_cpio = HashingFile::<sha2::Sha256, _>::new(rootfs_cpio_file);
        let mut status = Command::new("/usr/bin/env")
            .args(["cpio", "-i", "-d", "-u"])
            .current_dir(&self.rootfs_dir)
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to extract rootfs")?;

        {
            let mut stdin = status.stdin.take().context("Failed to get stdin")?;
            let mut buf = [0u8; 1024];
            loop {
                let n = hashing_rootfs_cpio
                    .read(&mut buf)
                    .context("Failed to read from rootfs cpio")?;
                if n == 0 {
                    break;
                }
                stdin
                    .write_all(&buf[..n])
                    .context("Failed to write to stdin")?;
            }
            drop(stdin);
        }
        let status = status.wait().context("Failed to wait for cpio")?;
        if !status.success() {
            bail!("Failed to extract rootfs, cpio returned {status:?}");
        }
        let rootfs_hash = hashing_rootfs_cpio.finalize();
        if &rootfs_hash[..] != expected_rootfs_hash {
            let expected = hex::encode(expected_rootfs_hash);
            let got = hex::encode(rootfs_hash);
            bail!("Rootfs hash mismatch, expected {expected}, got {got}");
        }
        info!("Rootfs hash is valid");
        fs::write(self.rootfs_dir.join(".rootfs_hash"), rootfs_hash)
            .context("Failed to write rootfs hash")?;
        cmd!(umount $cdrom_mnt)?;
        info!("Rootfs is ready");
        Ok(())
    }

    fn write_decrypted_env(&self, decrypted_env: &BTreeMap<String, String>) -> Result<()> {
        info!("Writing env");
        fs::write(
            self.host_shared_copy.join(DECRYPTED_ENV),
            env_process::convert_env_to_str(decrypted_env),
        )
        .context("Failed to write decrypted env file")?;
        let env_json = fs::File::create(self.host_shared_copy.join(DECRYPTED_ENV_JSON))
            .context("Failed to create env file")?;
        serde_json::to_writer(env_json, &decrypted_env)
            .context("Failed to write decrypted env file")?;
        Ok(())
    }

    async fn setup_rootfs(&self, host_shared: &HostShared, host: &HostApi) -> Result<()> {
        host.notify_q("boot.progress", "loading host-shared").await;
        let compose_hash = sha256_file(host_shared.dir.app_compose_file())?;
        let truncated_compose_hash = truncate(&compose_hash, 20);
        let kms_enabled = host_shared.app_compose.kms_enabled();
        let key_provider = host_shared.app_compose.key_provider();
        let mut instance_info = host_shared.instance_info.clone();
        let is_bootstrapped = instance_info.is_bootstrapped();

        if instance_info.app_id.is_empty() {
            instance_info.app_id = truncated_compose_hash.to_vec();
        }

        let disk_reusable = (!key_provider.is_none()) || !self.rootfs_encryption;
        if (!disk_reusable) || instance_info.instance_id_seed.is_empty() {
            instance_info.instance_id_seed = {
                let mut rand_id = vec![0u8; 20];
                getrandom::fill(&mut rand_id)?;
                rand_id
            };
        }
        let instance_id = if host_shared.app_compose.no_instance_id {
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

        host.notify_q("boot.progress", "extending RTMRs").await;

        extend_rtmr3("system-preparing", &[])?;
        extend_rtmr3("app-id", &instance_info.app_id)?;
        extend_rtmr3("compose-hash", &compose_hash)?;
        extend_rtmr3("instance-id", &instance_id)?;
        extend_rtmr3("boot-mr-done", &[])?;

        if host_shared.app_compose.key_provider().is_kms() {
            cmd_show_mrs()?;
        }

        host.notify_q("boot.progress", "requesting app keys").await;

        let app_keys = self.request_app_keys(host_shared, host).await?;
        if app_keys.disk_crypt_key.is_empty() {
            bail!("Failed to get valid key phrase from KMS");
        }
        host.notify_q("boot.progress", "decrypting env").await;
        let allowed_envs: BTreeSet<String> = host_shared
            .app_compose
            .allowed_envs
            .iter()
            .cloned()
            .collect();
        // Decrypt env file
        let decrypted_env = self.decrypt_env_vars(
            &app_keys.env_crypt_key,
            &host_shared.encrypted_env,
            &allowed_envs,
        )?;
        let disk_key = hex::encode(&app_keys.disk_crypt_key);
        if is_bootstrapped {
            host.notify_q("boot.progress", "mounting rootfs").await;
            self.mount_rootfs(&disk_key, host).await?;
        } else {
            host.notify_q("boot.progress", "initializing rootfs").await;
            self.bootstrap_rootfs(&disk_key, &instance_info, host)
                .await?;
        }
        self.write_decrypted_env(&decrypted_env)?;
        extend_rtmr3("system-ready", &[])?;
        host.notify_q("boot.progress", "rootfs ready").await;

        if !host_shared.app_compose.key_provider().is_kms() {
            cmd_show_mrs()?;
        }
        Ok(())
    }
}

fn emit_key_provider_info(provider_info: &KeyProviderInfo) -> Result<()> {
    info!("Key provider info: {provider_info:?}");
    let provider_info_json = serde_json::to_vec(&provider_info)?;
    extend_rtmr3("key-provider", &provider_info_json)?;
    Ok(())
}

pub async fn cmd_setup_fde(args: SetupFdeArgs) -> Result<()> {
    let host_shared = args.copy_host_shared()?;
    let host = HostApi::new(
        host_shared.vm_config.host_api_url.clone(),
        host_shared.vm_config.pccs_url.clone(),
    );
    match args.setup_rootfs(&host_shared, &host).await {
        Ok(_) => Ok(()),
        Err(err) => {
            host.notify_q("boot.error", &format!("{err:?}")).await;
            Err(err)
        }
    }
}
