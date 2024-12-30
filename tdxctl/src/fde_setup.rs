use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use fs_err as fs;
use kms_rpc::GetAppKeyRequest;
use ra_rpc::client::RaClient;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    cmd_gen_app_keys, cmd_gen_ra_cert, cmd_show,
    crypto::dh_decrypt,
    gen_app_keys_from_seed,
    host_api::HostApi,
    utils::{
        deserialize_json_file, extend_rtmr3, sha256, sha256_file, AppCompose, AppKeys, HashingFile,
        KeyProvider, LocalConfig,
    },
    GenAppKeysArgs, GenRaCertArgs,
};
use cmd_lib::run_cmd as cmd;
use serde_human_bytes as hex_bytes;

mod env_process;

#[derive(clap::Parser)]
/// Prepare full disk encryption
pub struct SetupFdeArgs {
    /// Host shared directory
    #[arg(long)]
    host_shared: PathBuf,
    /// Copied host-shared directory
    #[arg(long)]
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
    rootfs_encryption: std::primitive::bool,

    /// Rootfs hash
    #[arg(long, value_parser = parse_hex_bytes)]
    rootfs_hash: Vec<u8>,
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
    instance_id: Vec<u8>,
    #[serde(with = "hex_bytes", default)]
    app_id: Vec<u8>,
}

impl InstanceInfo {
    fn is_bootstrapped(&self) -> bool {
        self.bootstrapped.unwrap_or(!self.instance_id.is_empty())
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
        self.base_dir.join("app-compose.json")
    }

    fn encrypted_env_file(&self) -> PathBuf {
        self.base_dir.join("encrypted-env")
    }

    fn vm_config_file(&self) -> PathBuf {
        self.base_dir.join("config.json")
    }

    fn instance_info_file(&self) -> PathBuf {
        self.base_dir.join(".instance_info")
    }

    fn kms_ca_cert_file(&self) -> PathBuf {
        self.base_dir.join("certs").join("ca.cert")
    }

    fn tmp_ca_cert_file(&self) -> PathBuf {
        self.base_dir.join("certs").join("tmp-ca.cert")
    }

    fn tmp_ca_key_file(&self) -> PathBuf {
        self.base_dir.join("certs").join("tmp-ca.key")
    }
}

struct HostShared {
    dir: HostShareDir,
    vm_config: LocalConfig,
    app_compose: AppCompose,
    encrypted_env: Vec<u8>,
    instance_info: InstanceInfo,
}

impl HostShared {
    fn load(host_shared_dir: impl Into<HostShareDir>) -> Result<Self> {
        let host_shared_dir = host_shared_dir.into();
        let vm_config = deserialize_json_file(host_shared_dir.vm_config_file())?;
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
        self.host_shared_copy.join("appkeys.json")
    }

    fn copy_host_shared(&self) -> Result<HostShared> {
        let host_shared_dir = &self.host_shared;
        let host_shared_copy_dir = &self.host_shared_copy;
        cmd! {
            info "Mounting host-shared";
            mkdir -p $host_shared_dir;
            mount -t 9p -o trans=virtio,version=9p2000.L,ro host-shared $host_shared_dir;
            info "Copying host-shared";
            mkdir -p $host_shared_copy_dir;
            cp -r $host_shared_dir/. $host_shared_copy_dir;
            info "Unmounting host-shared";
            umount $host_shared_dir;
        }?;
        HostShared::load(host_shared_copy_dir.as_path())
    }

    async fn request_app_keys_from_kms(&self, host_shared: &HostShared) -> Result<()> {
        let Some(kms_url) = &host_shared.vm_config.kms_url else {
            bail!("KMS URL is not set");
        };
        info!("KMS is enabled, generating RA-TLS cert");
        let gen_certs_dir = self.work_dir.join("certs");
        fs::create_dir_all(&gen_certs_dir).context("Failed to create certs dir")?;
        cmd_gen_ra_cert(GenRaCertArgs {
            ca_cert: host_shared.dir.tmp_ca_cert_file(),
            ca_key: host_shared.dir.tmp_ca_key_file(),
            cert_path: gen_certs_dir.join("cert.pem"),
            key_path: gen_certs_dir.join("key.pem"),
        })?;
        info!("Requesting app keys from KMS: {kms_url}");
        let ra_client = RaClient::new_mtls(
            format!("{kms_url}/prpc"),
            fs::read_to_string(host_shared.dir.kms_ca_cert_file())?,
            fs::read_to_string(gen_certs_dir.join("cert.pem"))?,
            fs::read_to_string(gen_certs_dir.join("key.pem"))?,
        )?;
        let kms_client = kms_rpc::kms_client::KmsClient::new(ra_client);
        let response = kms_client
            .get_app_key(GetAppKeyRequest {
                upgradable: true,
                app_compose: fs::read_to_string(host_shared.dir.app_compose_file())
                    .context("Failed to read app compose file")?,
            })
            .await
            .context("Failed to get app key")?;
        let keys_json = serde_json::to_string(&response).context("Failed to serialize app keys")?;
        fs::write(self.app_keys_file(), keys_json).context("Failed to write app keys")?;
        extend_rtmr3("key-provider", b"{\"name\": \"kms\"}")?;
        Ok(())
    }

    async fn request_app_keys_from_local_key_provider(&self, host: &HostApi) -> Result<()> {
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
        let provider_info = serde_json::json!({
            "name": "gramine-sealing-key-provider",
            "mr": hex::encode(provision.mr),
        });
        let provider_info_json = serde_json::to_vec(&provider_info)?;
        extend_rtmr3("key-provider", &provider_info_json)?;
        Ok(())
    }

    async fn request_app_keys(&self, host_shared: &HostShared, host: &HostApi) -> Result<AppKeys> {
        let key_provider = host_shared.app_compose.key_provider();
        match key_provider {
            KeyProvider::Kms => self.request_app_keys_from_kms(host_shared).await?,
            KeyProvider::Local => self.request_app_keys_from_local_key_provider(host).await?,
            KeyProvider::None => {
                info!("No key provider is enabled, generating temporary app keys");
                cmd_gen_app_keys(GenAppKeysArgs {
                    ca_level: 1,
                    output: self.app_keys_file(),
                })?;
                extend_rtmr3("key-provider", b"{\"name\": \"none\"}")?;
            }
        }

        deserialize_json_file(self.app_keys_file()).context("Failed to decode app keys")
    }

    fn decrypt_env_vars(&self, key: &[u8], ciphertext: &[u8]) -> Result<BTreeMap<String, String>> {
        let vars = if !key.is_empty() && !ciphertext.is_empty() {
            info!("Processing encrypted env");
            let env_crypt_key: [u8; 32] = key
                .try_into()
                .ok()
                .context("Invalid env crypt key length")?;
            let decrypted_json =
                dh_decrypt(env_crypt_key, ciphertext).context("Failed to decrypt env file")?;
            env_process::parse_env(&decrypted_json)?
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
            if hash_file.exists() {
                fs::remove_file(&hash_file).context("Failed to remove old rootfs hash file")?;
            }
            host.notify_q("boot.progress", "upgrading rootfs").await;
            self.extract_rootfs(&self.rootfs_hash).await?;
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
            bail!("Rootfs hash mismatch");
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
            self.host_shared_copy.join("env"),
            env_process::convert_env_to_str(decrypted_env),
        )
        .context("Failed to write decrypted env file")?;
        let env_json = fs::File::create(self.host_shared_copy.join("env.json"))
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
        if (!disk_reusable) || instance_info.instance_id.is_empty() {
            instance_info.instance_id = {
                let mut rand_id = vec![0u8; 20];
                getrandom::getrandom(&mut rand_id)?;
                rand_id.extend_from_slice(&instance_info.app_id);
                sha256(&rand_id)[..20].to_vec()
            };
        }
        if !kms_enabled && instance_info.app_id != truncated_compose_hash {
            bail!("App upgrade is not supported without KMS");
        }

        let device_id = if key_provider.is_none() {
            Default::default()
        } else {
            let pre_key = host.get_sealing_key().await?;
            sha256(&pre_key.sk)
        };

        host.notify_q("boot.progress", "extending RTMRs").await;

        extend_rtmr3("system-preparing", &[])?;
        extend_rtmr3("device-id", &device_id)?;
        extend_rtmr3("rootfs-hash", &self.rootfs_hash)?;
        extend_rtmr3("app-id", &instance_info.app_id)?;
        extend_rtmr3("compose-hash", &compose_hash)?;
        extend_rtmr3("instance-id", &instance_info.instance_id)?;

        if kms_enabled {
            let ca_cert_hash = sha256_file(host_shared.dir.kms_ca_cert_file())?;
            extend_rtmr3("ca-cert-hash", &ca_cert_hash)?;
        }

        // Show the RTMR
        cmd_show()?;

        host.notify_q("boot.progress", "requesting app keys").await;

        let app_keys = self.request_app_keys(host_shared, host).await?;
        if app_keys.disk_crypt_key.is_empty() {
            bail!("Failed to get valid key phrase from KMS");
        }
        host.notify_q("boot.progress", "decrypting env").await;
        // Decrypt env file
        let decrypted_env =
            self.decrypt_env_vars(&app_keys.env_crypt_key, &host_shared.encrypted_env)?;
        if is_bootstrapped {
            host.notify_q("boot.progress", "mounting rootfs").await;
            self.mount_rootfs(&app_keys.disk_crypt_key, host).await?;
        } else {
            host.notify_q("boot.progress", "initializing rootfs").await;
            self.bootstrap_rootfs(&app_keys.disk_crypt_key, &instance_info, host)
                .await?;
        }
        self.write_decrypted_env(&decrypted_env)?;
        extend_rtmr3("system-ready", &[])?;
        host.notify_q("boot.progress", "rootfs ready").await;
        Ok(())
    }
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
