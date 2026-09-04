// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, net::IpAddr, path::PathBuf, process::Command, str::FromStr};

use anyhow::{bail, Context, Result};
use load_config::load_config;
use path_absolutize::Absolutize;
use rocket::figment::Figment;
use serde::{Deserialize, Serialize};

use dstack_types::TdxAttestationVariant;
use lspci::{lspci_filtered, Device};
use tracing::{info, warn};

pub const DEFAULT_CONFIG: &str = include_str!("../vmm.toml");

fn detect_qemu_version(qemu_path: &PathBuf) -> Result<String> {
    let output = Command::new(qemu_path)
        .arg("--version")
        .output()
        .context("Failed to execute qemu --version")?;

    if !output.status.success() {
        bail!("QEMU version command failed with status: {}", output.status);
    }

    let version_output =
        String::from_utf8(output.stdout).context("QEMU version output is not valid UTF-8")?;

    parse_qemu_version_from_output(&version_output)
        .context("Could not parse QEMU version from output")
}

fn parse_qemu_version_from_output(output: &str) -> Result<String> {
    // Parse version from output like:
    // "QEMU emulator version 8.2.2 (Debian 2:8.2.2+ds-0ubuntu1.4+tdx1.0)"
    // "QEMU emulator version 9.1.0"
    let version = output
        .lines()
        .next()
        .and_then(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();

            // First try: Look for "version" keyword and get the next word (only if it looks like a version)
            if let Some(version_idx) = words.iter().position(|&word| word == "version") {
                if let Some(next_word) = words.get(version_idx + 1) {
                    // Only use the word after "version" if it looks like a version number
                    if next_word.chars().next().is_some_and(|c| c.is_ascii_digit())
                        && (next_word.contains('.')
                            || next_word.chars().all(|c| c.is_ascii_digit() || c == '-'))
                    {
                        return Some(*next_word);
                    }
                }
            }

            // Fallback: find first word that looks like a version number
            words
                .iter()
                .find(|word| {
                    // Check if word starts with digit and contains dots (version-like)
                    word.chars().next().is_some_and(|c| c.is_ascii_digit())
                        && (word.contains('.')
                            || word.chars().all(|c| c.is_ascii_digit() || c == '-'))
                })
                .copied()
        })
        .context("Could not parse QEMU version from output")?;

    // Extract just the version number (e.g., "8.2.2" from "8.2.2+ds-0ubuntu1.4+tdx1.0")
    let clean_version = version.split('+').next().unwrap_or(version).to_string();

    Ok(clean_version)
}

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("vmm", DEFAULT_CONFIG, config_file, false)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => bail!("Invalid protocol: {s}"),
        })
    }
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CvmPlatform {
    Tdx,
    AmdSevSnp,
}

impl CvmPlatform {
    /// Detect the host TEE platform from /proc/cpuinfo. Used when the operator
    /// did not pin a platform in the config (`platform` omitted, or `auto`).
    pub fn detect() -> Self {
        Self::resolve_from_cpuinfo(&fs_err::read_to_string("/proc/cpuinfo").unwrap_or_default())
    }

    pub fn resolve_from_cpuinfo(cpuinfo: &str) -> Self {
        // Detect the host TEE from /proc/cpuinfo CPU flags:
        //   - AMD SEV-SNP hosts advertise the `sev_snp` flag
        //   - Intel TDX hosts advertise the `tdx_host_platform` flag
        // These flags are vendor-exclusive, so the flag alone is unambiguous.
        // Anything else falls back to TDX (the conservative default; the VMM is
        // expected to run on a TEE host). Operators can always override the
        // detection with an explicit `platform = "tdx" | "amd-sev-snp"`.
        let has_flag = |flag: &str| {
            cpuinfo
                .lines()
                .filter(|line| line.starts_with("flags") || line.starts_with("Features"))
                .any(|line| line.split_whitespace().any(|f| f == flag))
        };
        if has_flag("sev_snp") {
            Self::AmdSevSnp
        } else {
            Self::Tdx
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortRange {
    pub protocol: Protocol,
    pub from: u16,
    pub to: u16,
}

impl PortRange {
    pub fn contains(&self, protocol: &str, port: u16) -> bool {
        self.protocol.as_str() == protocol && port >= self.from && port <= self.to
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortMappingConfig {
    pub enabled: bool,
    pub address: IpAddr,
    pub range: Vec<PortRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoRestartConfig {
    pub enabled: bool,
    /// How often the supervisor state is sampled.
    pub interval: u64,
    /// Maximum consecutive automatic restart attempts before intervention.
    pub max_retries: u32,
    /// Delay before the first retry. Later retries use exponential backoff.
    pub initial_backoff: u64,
    /// Upper bound for the exponential retry delay.
    pub max_backoff: u64,
    /// Continuous healthy runtime required to reset the retry budget.
    pub reset_window: u64,
}

/// Retention for the logs a CVM writes into its work directory.
///
/// Currently governs serial.log. The caps are deliberately not named after it,
/// because rotation itself is generic (see `crate::logrotate`) and stdout/stderr
/// are the obvious next call sites.
#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    /// Max size of a live log. QEMU appends to serial.log for the whole life of
    /// a boot, so without a cap a chatty guest can fill the host disk. Past
    /// this size the log is rotated and truncated in place. 0 disables
    /// rotation.
    #[serde(with = "size_parser::human_size")]
    pub max_bytes: u64,

    /// Rotated segments to keep. Follows logrotate semantics: the oldest is
    /// discarded.
    pub max_backups: usize,

    /// How often a live log is checked against `max_bytes`, in seconds.
    pub check_interval_secs: u64,
}

impl AutoRestartConfig {
    pub fn validate(&self) -> Result<()> {
        if self.enabled {
            if self.interval == 0 {
                bail!("cvm.auto_restart.interval must be greater than zero when enabled");
            }
            if self.initial_backoff == 0 {
                bail!("cvm.auto_restart.initial_backoff must be greater than zero when enabled");
            }
            if self.initial_backoff > self.max_backoff {
                bail!("cvm.auto_restart.initial_backoff must not exceed max_backoff");
            }
        }
        Ok(())
    }
}

impl PortMappingConfig {
    pub fn is_allowed(&self, protocol: &str, port: u16) -> bool {
        if !self.enabled {
            return false;
        }
        self.range.iter().any(|r| r.contains(protocol, port))
    }
}

/// Deserialize the optional `platform` config field. `None` (field omitted, or
/// the legacy literal `auto`) means "detect the host TEE"; `tdx` / `amd-sev-snp`
/// pin a platform. Keeping `auto` accepted preserves existing vmm.toml configs.
fn deserialize_platform<'de, D>(deserializer: D) -> Result<Option<CvmPlatform>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    enum PlatformSetting {
        Auto,
        Tdx,
        AmdSevSnp,
    }
    Ok(
        match Option::<PlatformSetting>::deserialize(deserializer)? {
            None | Some(PlatformSetting::Auto) => None,
            Some(PlatformSetting::Tdx) => Some(CvmPlatform::Tdx),
            Some(PlatformSetting::AmdSevSnp) => Some(CvmPlatform::AmdSevSnp),
        },
    )
}

impl CvmConfig {
    /// The effective TEE platform: the configured one, or host auto-detection
    /// when left unset (`platform` omitted / `auto`).
    pub fn resolved_platform(&self) -> CvmPlatform {
        self.platform.unwrap_or_else(CvmPlatform::detect)
    }
}

/// VMM-side policy for selecting the TDX attestation/hash scheme.
///
/// This is intentionally separate from `dstack_types::TdxAttestationVariant`:
/// the VM config shared with KMS/verifier must contain the resolved runtime
/// variant (`legacy` or `lite`), never the VMM-only `auto` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TdxAttestationVariantConfig {
    Legacy,
    Lite,
    #[default]
    Auto,
}

impl TdxAttestationVariantConfig {
    const TWO_GIB_MIB: u32 = 2 * 1024;
    const THREE_GIB_MIB: u32 = 3 * 1024;

    pub fn resolve(self, memory_mib: u32, image_supports_lite: bool) -> TdxAttestationVariant {
        match self {
            Self::Legacy => TdxAttestationVariant::Legacy,
            Self::Lite => TdxAttestationVariant::Lite,
            Self::Auto => {
                if memory_mib < Self::THREE_GIB_MIB && memory_mib != Self::TWO_GIB_MIB {
                    TdxAttestationVariant::Legacy
                } else if image_supports_lite {
                    TdxAttestationVariant::Lite
                } else {
                    TdxAttestationVariant::Legacy
                }
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CvmConfig {
    /// TEE platform to use when launching CVMs. Omit (or set `auto`) to detect
    /// the host TEE from /proc/cpuinfo (AMD SEV-SNP vs Intel TDX); set `tdx` or
    /// `amd-sev-snp` to force a platform.
    #[serde(default, deserialize_with = "deserialize_platform")]
    pub platform: Option<CvmPlatform>,
    pub qemu_path: PathBuf,
    /// The URL of the KMS server
    pub kms_urls: Vec<String>,
    /// Randomize KMS failover order independently for each CVM.
    #[serde(default)]
    pub shuffle_kms_urls: bool,
    /// The URL of the dstack-gateway server
    #[serde(alias = "tproxy_urls")]
    pub gateway_urls: Vec<String>,
    /// Independently operated gateway clusters. URLs in each entry are
    /// failover endpoints for that cluster.
    #[serde(default)]
    pub gateway_clusters: Vec<dstack_types::GatewayClusterConfig>,
    /// Randomize gateway failover order independently for each CVM.
    #[serde(default)]
    pub shuffle_gateway_urls: bool,
    /// The URL of the PCCS server
    #[serde(default)]
    pub pccs_url: String,
    /// Node-local credentials and collateral settings used when an individual
    /// VM requests a simulated TEE platform.
    #[serde(default)]
    pub tee_simulator: Option<dstack_types::TeeSimulatorConfig>,
    /// Optional NVIDIA OCSP/RIM cache passed to guests in sys-config.
    #[serde(default)]
    pub nvidia_attestation_proxy_url: Option<String>,
    /// The URL of the Docker registry
    pub docker_registry: String,
    /// The start of the CID pool that allocates CIDs to VMs
    pub cid_start: u32,
    /// The size of the CID pool that allocates CIDs to VMs
    pub cid_pool_size: u32,
    /// Port mapping configuration
    pub port_mapping: PortMappingConfig,
    /// Max allocable resources. Not yet implement fully, only for inspect API `GetMeta`
    pub max_allocable_vcpu: u32,
    pub max_allocable_memory_in_mb: u32,
    /// Enable qmp socket
    pub qmp_socket: bool,
    /// GPU configuration
    pub gpu: GpuConfig,
    /// Auto restart configuration
    pub auto_restart: AutoRestartConfig,

    /// Use mrconfigid instead of compose hash
    pub use_mrconfigid: bool,

    /// QEMU single pass add page
    pub qemu_single_pass_add_pages: Option<bool>,
    /// QEMU pic
    pub qemu_pic: Option<bool>,
    /// QEMU qemu_version
    pub qemu_version: Option<String>,
    /// QEMU pci_hole64_size
    #[serde(with = "size_parser::human_size")]
    pub qemu_pci_hole64_size: u64,
    /// QEMU hotplug_off
    pub qemu_hotplug_off: bool,
    /// TDX attestation/hash scheme policy. `legacy` keeps the existing
    /// digest.txt measurement path; `lite` opts into split measurement CBOR;
    /// `auto` selects `legacy` for
    /// CVMs below 3 GiB except exactly 2 GiB, otherwise uses `lite` when the
    /// image carries TDX measurement material and falls back to `legacy`.
    #[serde(default)]
    pub tdx_attestation_variant: TdxAttestationVariantConfig,

    /// Networking configuration
    pub networking: Networking,

    /// Network backends that deployment RPC callers may request explicitly.
    /// The node default is still used when a request omits networking.
    #[serde(default = "default_allowed_network_modes")]
    pub allowed_network_modes: Vec<NetworkingMode>,

    /// Host bridges that deployment RPC callers may select explicitly.
    /// An empty list permits only the node's default bridge.
    #[serde(default)]
    pub allowed_bridges: Vec<String>,

    /// Host interfaces that deployment RPC callers may select explicitly as
    /// macvtap parents. An empty list permits only the node default parent.
    #[serde(default)]
    pub allowed_macvtap_parents: Vec<String>,

    /// Largest virtio-net queue pair count a deployment RPC caller may request.
    /// There is no node-wide count for it to bind; lowering it below the
    /// scaling cap does lower the vCPU-scaled default too.
    #[serde(default = "default_max_net_queues")]
    pub max_net_queues: u32,

    /// Optional host-side filtering for bridge interfaces. This filter does
    /// not apply to macvtap interfaces.
    #[serde(default)]
    pub network_filter: NetworkFilterConfig,

    /// Stable namespace for TAP names when several VMMs share one host.
    /// An empty value is derived from the absolute run directory.
    #[serde(default)]
    pub instance_id: String,

    /// Host sharing mode. (9p, vhd, vvfat)
    pub host_share_mode: String,

    /// QGS (Quote Generation Service) vsock port for kernel-level TSM support.
    /// When set, QEMU will pass this port to tdx-guest for configfs-tsm quote generation.
    /// The guest kernel will use this vsock port to communicate with the host QGS.
    /// Default is None (disabled), common value is 4050.
    pub qgs_port: Option<u32>,

    /// SMBIOS product information for cloud environment detection
    #[serde(default)]
    pub product: ProductConfig,

    /// Guest log retention.
    pub log: LogConfig,

    /// Directory holding attachable volume images (e.g. pre-baked verity
    /// volumes). A deploy may only attach files under this directory, referenced
    /// by bare file name. Empty (the default) disables volume attachment.
    #[serde(default)]
    pub volumes_dir: String,
}

/// SMBIOS product information configuration.
/// Field names correspond to /sys/class/dmi/id/ entries in guest.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProductConfig {
    // SMBIOS type=0 (BIOS Information)
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub bios_date: Option<String>,
    pub bios_release: Option<String>,

    // SMBIOS type=1 (System Information)
    pub sys_vendor: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub product_serial: Option<String>,
    pub product_uuid: Option<String>,
    pub product_family: Option<String>,
    pub product_sku: Option<String>,

    // SMBIOS type=2 (Baseboard Information)
    pub board_vendor: Option<String>,
    pub board_name: Option<String>,
    pub board_version: Option<String>,
    pub board_serial: Option<String>,
    pub board_asset_tag: Option<String>,

    // SMBIOS type=3 (Chassis Information)
    pub chassis_vendor: Option<String>,
    pub chassis_version: Option<String>,
    pub chassis_serial: Option<String>,
    pub chassis_asset_tag: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GpuConfig {
    /// Whether to enable GPU passthrough
    pub enabled: bool,
    /// The product IDs of the GPUs to discover
    pub listing: Vec<String>,
    /// The PCI addresses to exclude from passthrough
    pub exclude: Vec<String>,
    /// The PCI addresses to include in passthrough
    pub include: Vec<String>,
    /// Allow attach all GPUs
    pub allow_attach_all: bool,
    /// Reset each GPU's dedicated upstream PCIe bus before QEMU attaches it.
    pub sanitize_on_attach: bool,
    /// Shared deadline for all GPUs to become VFIO-ready after SBR.
    pub sbr_timeout_ms: u64,
}

impl GpuConfig {
    pub(crate) fn list_devices(&self) -> Result<Vec<Device>> {
        let devices = lspci_filtered(|dev| {
            if !self.listing.contains(&dev.full_product_id()) {
                return false;
            }
            if self.exclude.contains(&dev.slot) {
                return false;
            }
            if !self.include.is_empty() && !self.include.contains(&dev.slot) {
                return false;
            }
            true
        })
        .context("Failed to list GPU devices")?;

        info!(
            "Found {} GPUs, {} in use",
            devices.len(),
            devices.iter().filter(|d| d.in_use()).count()
        );
        Ok(devices)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// Whether to enable API token authentication
    pub enabled: bool,
    /// The API tokens
    pub tokens: Vec<String>,
    /// Optional Apache htpasswd file for HTTP Basic authentication.
    #[serde(default)]
    pub htpasswd_file: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SupervisorConfig {
    pub exe: String,
    pub sock: String,
    pub pid_file: String,
    pub log_file: String,
    pub detached: bool,
    pub auto_start: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub base_domain: String,
    pub port: u16,
    pub agent_port: u16,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ImageConfig {
    /// Path to guest image directory
    #[serde(default)]
    pub path: PathBuf,
    /// OCI image registry for guest images (e.g., "dstacktee/guest-image")
    #[serde(default)]
    pub registry: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Deprecated: use `[image] path` instead. Kept for backward compatibility.
    #[serde(default)]
    image_path: PathBuf,
    #[serde(default)]
    pub run_path: PathBuf,
    /// The URL of the KMS server
    pub kms_url: String,

    /// Node name (optional, used as prefix in UI title)
    #[serde(default)]
    pub node_name: String,

    /// Image configuration
    #[serde(default)]
    pub image: ImageConfig,

    /// The buffer size in VMM process for guest events
    pub event_buffer_size: usize,

    /// CVM configuration
    pub cvm: CvmConfig,

    /// Privileged host networking service configuration.
    #[serde(default)]
    pub netd: NetdConfig,
    /// Gateway configuration
    pub gateway: GatewayConfig,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Supervisor configuration
    pub supervisor: SupervisorConfig,

    /// Host API configuration
    pub host_api: HostApiConfig,

    /// Key provider configuration
    pub key_provider: KeyProviderConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkFilterMode {
    #[default]
    None,
    Libvirt,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkFilterConfig {
    #[serde(default)]
    pub mode: NetworkFilterMode,
    #[serde(default = "default_libvirt_filter")]
    pub filter: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, String>,
}

impl NetworkFilterConfig {
    /// Whether every bridge TAP on this node must carry an nwfilter binding.
    pub fn requires_binding(&self) -> bool {
        self.mode == NetworkFilterMode::Libvirt
    }
}

impl Default for NetworkFilterConfig {
    fn default() -> Self {
        Self {
            mode: NetworkFilterMode::None,
            filter: default_libvirt_filter(),
            parameters: BTreeMap::new(),
        }
    }
}

fn default_libvirt_filter() -> String {
    "clean-traffic".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetdConfig {
    #[serde(default = "default_netd_socket")]
    pub socket: PathBuf,
    /// Filesystem permissions applied when netd creates its own socket.
    /// Systemd-activated sockets use `SocketMode` from the socket unit.
    pub socket_mode: u32,
    #[serde(default = "default_libvirt_uri")]
    pub libvirt_uri: String,
    /// The bridge filtering policy netd enforces and applies: whether a binding
    /// is required, which nwfilter it names, and with what parameters.
    ///
    /// netd holds this itself rather than taking it from each request. It is
    /// the privileged side of the socket, and a caller that chose the filter
    /// could name one that drops nothing -- `allow-arp` has no drop rule at all
    /// -- or pin `clean-traffic` to the gateway's MAC and IP through its
    /// parameters, and still satisfy a policy that only asked for "some
    /// filter".
    ///
    /// Unset derives it from `cvm.network_filter` in the same file, which is
    /// the whole answer whenever netd and the VMM share one `vmm.toml` -- the
    /// normal deployment. Set it explicitly when netd runs with a config that
    /// carries no `[cvm]` section, so the daemon holding the privilege is never
    /// left inferring policy from a file that does not state it.
    #[serde(default)]
    pub network_filter: Option<NetworkFilterConfig>,
    /// How often the VMM asks netd to collect interfaces no VM of its claims.
    ///
    /// The pass at startup is not optional and does not read this: it is the
    /// one moment the VMM knows every VM it has, and everything a crash left
    /// behind is still there. This is the backstop for what accumulates while
    /// it runs -- a removal that raced a netd outage, an interface a stop could
    /// not reach. Zero turns it off.
    #[serde(default = "default_reconcile_interval")]
    pub reconcile_interval_secs: u64,
    /// Whether a collection may delete interfaces it cannot attribute.
    ///
    /// Off. An interface carrying no ownership record is not nobody's: on a
    /// host where two VMM instances share one netd, it may be the other one's
    /// running VM, and before netd recorded ownership every interface looked
    /// like this. Turn it on only where nothing else creates interfaces in
    /// netd's name space -- a single VMM instance on the host.
    #[serde(default)]
    pub collect_unattributed: bool,
}

/// See [`NetdConfig::reconcile_interval_secs`].
fn default_reconcile_interval() -> u64 {
    3600
}

impl Default for NetdConfig {
    fn default() -> Self {
        Self {
            socket: default_netd_socket(),
            socket_mode: 0o660,
            libvirt_uri: default_libvirt_uri(),
            network_filter: None,
            reconcile_interval_secs: default_reconcile_interval(),
            collect_unattributed: false,
        }
    }
}

impl NetdConfig {
    /// Resolved policy. Unset means the config named no `[cvm]` section to
    /// derive it from, and an unfiltered node is the historical shape.
    pub fn filter_policy(&self) -> &NetworkFilterConfig {
        static UNFILTERED: std::sync::OnceLock<NetworkFilterConfig> = std::sync::OnceLock::new();
        self.network_filter
            .as_ref()
            .unwrap_or_else(|| UNFILTERED.get_or_init(NetworkFilterConfig::default))
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.socket_mode & !0o777 == 0,
            "netd.socket_mode must contain only Unix permission bits"
        );
        Ok(())
    }
}

fn default_netd_socket() -> PathBuf {
    PathBuf::from("/run/dstack/netd.sock")
}

fn default_libvirt_uri() -> String {
    "qemu:///system".to_string()
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ProcessAnnotation {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub live_for: Option<String>,
    /// Whether this process's serial chardev log was opened with
    /// `logappend=on`, which is what makes rotating it in place safe.
    ///
    /// Absent for processes launched before this option existed, and `default`
    /// makes those deserialize to `false` — the conservative answer.
    #[serde(default)]
    pub serial_logappend: bool,
}

impl ProcessAnnotation {
    pub fn is_cvm(&self) -> bool {
        if self.live_for.is_some() {
            return false;
        }
        self.kind.is_empty() || self.kind == "cvm"
    }
}

impl Config {
    pub fn abs_path(mut self) -> Result<Self> {
        self.image.path = self.image.path.absolutize()?.to_path_buf();
        self.run_path = self.run_path.absolutize()?.to_path_buf();
        Ok(self)
    }

    /// Validate configuration invariants that do not require starting services
    /// or modifying host state.
    pub fn validate(&self) -> Result<()> {
        self.host_api
            .validate()
            .context("Invalid host_api configuration")?;

        self.netd.validate()?;

        anyhow::ensure!(self.cvm.cid_start >= 3, "cvm.cid_start must be at least 3");
        anyhow::ensure!(
            self.cvm.cid_pool_size > 0,
            "cvm.cid_pool_size must be greater than zero"
        );
        self.cvm
            .cid_start
            .checked_add(self.cvm.cid_pool_size)
            .context("cvm CID pool overflows u32")?;

        anyhow::ensure!(
            matches!(self.cvm.host_share_mode.as_str(), "9p" | "vhd" | "vvfat"),
            "cvm.host_share_mode must be one of: 9p, vhd, vvfat"
        );
        if self.cvm.auto_restart.enabled {
            anyhow::ensure!(
                self.cvm.auto_restart.interval > 0,
                "cvm.auto_restart.interval must be greater than zero when enabled"
            );
        }
        for range in &self.cvm.port_mapping.range {
            anyhow::ensure!(
                range.from <= range.to,
                "cvm.port_mapping range start {} exceeds end {}",
                range.from,
                range.to
            );
        }

        validate_networking(&self.cvm.networking)?;
        // netd creates an unfiltered TAP when the filter name is empty, which
        // is what unfiltered multiqueue bridges need. Libvirt mode must never
        // reach that path: it would silently produce an unbound TAP where the
        // operator asked for a filtered one.
        anyhow::ensure!(
            self.cvm.network_filter.mode != NetworkFilterMode::Libvirt
                || !self.cvm.network_filter.filter.trim().is_empty(),
            "cvm.network_filter.filter must not be empty when mode is libvirt"
        );
        anyhow::ensure!(
            (1..=MAX_NET_QUEUES).contains(&self.cvm.max_net_queues),
            "cvm.max_net_queues must be between 1 and {MAX_NET_QUEUES}"
        );
        anyhow::ensure!(
            !self
                .cvm
                .allowed_network_modes
                .contains(&NetworkingMode::Custom),
            "cvm.allowed_network_modes cannot contain custom"
        );
        for (name, values) in [
            ("cvm.allowed_bridges", &self.cvm.allowed_bridges),
            (
                "cvm.allowed_macvtap_parents",
                &self.cvm.allowed_macvtap_parents,
            ),
        ] {
            anyhow::ensure!(
                values.iter().all(|value| !value.trim().is_empty()),
                "{name} cannot contain empty interface names"
            );
        }
        anyhow::ensure!(
            !self.supervisor.sock.trim().is_empty(),
            "supervisor.sock must not be empty"
        );
        if self.supervisor.auto_start {
            for (name, value) in [
                ("supervisor.exe", self.supervisor.exe.as_str()),
                ("supervisor.pid_file", self.supervisor.pid_file.as_str()),
                ("supervisor.log_file", self.supervisor.log_file.as_str()),
            ] {
                anyhow::ensure!(
                    !value.trim().is_empty(),
                    "{name} must not be empty when supervisor.auto_start is enabled"
                );
            }
        }

        for (name, values) in [
            ("cvm.kms_urls", self.cvm.kms_urls.as_slice()),
            ("cvm.gateway_urls", self.cvm.gateway_urls.as_slice()),
        ] {
            for value in values {
                validate_http_url(name, value)?;
            }
        }
        anyhow::ensure!(
            self.cvm.gateway_urls.is_empty() || self.cvm.gateway_clusters.is_empty(),
            "cvm.gateway_urls and cvm.gateway_clusters cannot both be configured"
        );
        let mut cluster_names = std::collections::HashSet::new();
        for cluster in &self.cvm.gateway_clusters {
            anyhow::ensure!(
                !cluster.name.is_empty()
                    && cluster
                        .name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "invalid cvm.gateway_clusters name: {}",
                cluster.name
            );
            anyhow::ensure!(
                cluster_names.insert(cluster.name.as_str()),
                "duplicate cvm.gateway_clusters name: {}",
                cluster.name
            );
            anyhow::ensure!(
                !cluster.urls.is_empty(),
                "cvm.gateway_clusters.{} must contain at least one URL",
                cluster.name
            );
            for url in &cluster.urls {
                validate_http_url("cvm.gateway_clusters.urls", url)?;
            }
        }
        for (name, value) in [
            ("cvm.pccs_url", Some(self.cvm.pccs_url.as_str())),
            (
                "cvm.nvidia_attestation_proxy_url",
                self.cvm.nvidia_attestation_proxy_url.as_deref(),
            ),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                validate_http_url(name, value)?;
            }
        }
        Ok(())
    }
}

fn validate_http_url(name: &str, value: &str) -> Result<()> {
    let url = url::Url::parse(value).with_context(|| format!("{name} contains an invalid URL"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "{name} URL must use http or https: {value}"
    );
    anyhow::ensure!(
        url.host().is_some(),
        "{name} URL must include a host: {value}"
    );
    Ok(())
}

fn validate_networking(networking: &Networking) -> Result<()> {
    let prefix = networking.mac_prefix.as_str();
    if !prefix.is_empty() {
        let bytes = prefix.split(':').collect::<Vec<_>>();
        anyhow::ensure!(
            bytes.len() <= 3
                && bytes
                    .iter()
                    .all(|byte| byte.len() == 2 && u8::from_str_radix(byte, 16).is_ok()),
            "cvm.networking.mac_prefix must contain 1 to 3 two-digit hexadecimal bytes"
        );
    }
    anyhow::ensure!(
        networking.nic.queues.is_none(),
        "cvm.networking.queues is not a node setting; queue pairs follow each VM's vCPU count, \
         bounded by cvm.max_net_queues, and a deployment overrides them per NIC"
    );
    // Both describe a per-VM entry's relationship to this configuration, so
    // neither means anything on the node default itself.
    anyhow::ensure!(
        !networking.nic.inherit_mode,
        "cvm.networking.inherit_mode is per-deployment state and cannot be set on the node default"
    );
    anyhow::ensure!(
        networking.netd_interface.is_none(),
        "cvm.networking.netd_interface is runtime state and cannot be set in configuration"
    );
    anyhow::ensure!(
        networking.device.is_empty(),
        "cvm.networking.device is runtime state and cannot be set in configuration"
    );
    match networking.nic.mode {
        NetworkingMode::Bridge => anyhow::ensure!(
            !networking.nic.bridge.trim().is_empty(),
            "cvm.networking.bridge must not be empty in bridge mode"
        ),
        NetworkingMode::Custom => anyhow::ensure!(
            !networking.netdev.trim().is_empty(),
            "cvm.networking.netdev must not be empty in custom mode"
        ),
        NetworkingMode::Macvtap => {
            anyhow::ensure!(
                !networking.nic.parent.trim().is_empty(),
                "cvm.networking.parent must not be empty in macvtap mode"
            );
            anyhow::ensure!(
                matches!(
                    networking.macvtap_mode.as_str(),
                    "" | "private" | "bridge" | "vepa" | "passthru"
                ),
                "cvm.networking.macvtap_mode must be private, bridge, vepa, or passthru"
            );
        }
        // User mode has no identity fields of its own to check.
        NetworkingMode::User => {}
    }
    Ok(())
}

fn default_allowed_network_modes() -> Vec<NetworkingMode> {
    vec![NetworkingMode::User, NetworkingMode::Bridge]
}

fn default_max_net_queues() -> u32 {
    DEFAULT_MAX_NET_QUEUES
}

/// Where the vCPU-scaled default stops growing. Each queue pair costs a host
/// vhost thread and two MSI-X vectors, and cross-vCPU wakeups are expensive
/// under TDX, so the benefit runs out well before a large VM's vCPU count.
/// Raising `cvm.max_net_queues` lets a deployment ask for more; it does not
/// move this, because a bigger VM should not silently get a worse default.
pub const DEFAULT_QUEUE_SCALING_CAP: u32 = 16;

/// Default ceiling on what a deployment RPC caller may request.
pub const DEFAULT_MAX_NET_QUEUES: u32 = 16;

/// Hard bound on queue pairs from any source, well below anything QEMU or the
/// guest driver would refuse. It exists so a malformed or hostile request
/// cannot ask the host kernel for an unbounded device, not because 64 is a
/// property of virtio-net.
pub const MAX_NET_QUEUES: u32 = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkingMode {
    /// The backend that needs nothing from the host, so it is what a NIC that
    /// names none falls back to.
    #[default]
    User,
    Bridge,
    Custom,
    Macvtap,
}

impl NetworkingMode {
    /// The name this mode is written as in `vmm.toml`, in the RPC, and in
    /// anything an operator reads.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkingMode::User => "user",
            NetworkingMode::Bridge => "bridge",
            NetworkingMode::Custom => "custom",
            NetworkingMode::Macvtap => "macvtap",
        }
    }
}

/// What a single NIC pins: the fields a deployment may name, a VM's manifest
/// stores, and `GetInfo` reports back.
///
/// Separate from [`Networking`] because the node's `[cvm.networking]` is not a
/// NIC -- it is a NIC *plus* the backend settings only the node may set. When
/// the two were one type, resolution copied the whole node value into every
/// VM, so a bridge NIC's manifest entry carried whatever macvtap parent the
/// node happened to have configured, and every consumer that asked "what does
/// this VM pin?" had to know which fields to ignore. Several did not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct NicNetworking {
    pub mode: NetworkingMode,

    // ── Bridge fields ──────────────────────────────────────────────
    /// Bridge interface to attach TAP device to (e.g., "virbr0")
    #[serde(default)]
    pub bridge: String,

    // ── Macvtap fields ────────────────────────────────────────────
    /// Parent host interface for macvtap (e.g., "eth0").
    #[serde(default)]
    pub parent: String,

    // ── Data plane tuning ──────────────────────────────────────────
    /// Move packet processing from the QEMU main loop into the host kernel's
    /// vhost-net data plane. `None` inherits the node default. Ignored by the
    /// user-mode backend, which has no vhost support, and by custom mode,
    /// which owns its whole netdev string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vhost: Option<bool>,
    /// virtio-net queue pairs. `None` scales with the VM's vCPU count. Only a
    /// deployment sets this; there is no node-wide value, because the useful
    /// number depends on the VM rather than the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queues: Option<u32>,

    // ── Ownership markers ──────────────────────────────────────────
    /// Take `mode` from node configuration at every launch instead of from
    /// this entry.
    ///
    /// A deployment that only tunes the data plane never named a backend, so
    /// the node still owns which one this NIC uses. `mode` is not an `Option`
    /// -- every consumer matches on it -- so the entry carries the node's
    /// current mode and this flag says not to trust it across a node
    /// configuration change.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub inherit_mode: bool,
}

/// `[cvm.networking]`, and the resolved value a launch hands to QEMU: one NIC
/// plus the backend settings that belong to the node rather than to any VM.
///
/// Resolution produces this same type because a launch needs both halves; what
/// it must never do is hand the node half back to a VM to store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Networking {
    #[serde(flatten)]
    pub nic: NicNetworking,

    // ── Macvtap fields ────────────────────────────────────────────
    /// macvtap forwarding mode. Empty selects "private".
    #[serde(default)]
    pub macvtap_mode: String,
    /// Runtime-only character device returned by netd.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,

    // ── MAC prefix ─────────────────────────────────────────────────
    /// Fixed MAC address prefix (0-3 colon-separated hex bytes, e.g. "02:ab:cd").
    /// Remaining bytes are derived from the VM ID hash.
    #[serde(default)]
    pub mac_prefix: String,

    // ── User-mode fields ───────────────────────────────────────────
    #[serde(default)]
    pub net: String,
    #[serde(default)]
    pub dhcp_start: String,
    #[serde(default)]
    pub restrict: bool,

    // ── Custom fields ──────────────────────────────────────────────
    #[serde(default)]
    pub netdev: String,

    // ── Runtime markers ────────────────────────────────────────────
    /// What netd built for this NIC, recorded when it was built.
    ///
    /// Runtime state, like `device`: resolution always clears it. Teardown
    /// reads this rather than re-deriving it from node configuration, because
    /// an operator may change `network_filter.mode` or `max_net_queues` while
    /// the VM runs, and what has to be removed is what was created.
    #[serde(default, skip_serializing_if = "NetdInterface::is_none")]
    pub netd_interface: NetdInterface,
    /// The host ports netd actually published for this NIC.
    ///
    /// Runtime state, like `device`: resolution always clears it. What was
    /// asked for lives in the manifest; this is what was answered, and the
    /// difference between the two is the whole reason to keep it. Reporting
    /// the request as though it were the answer is how a VM's ports could be
    /// listed as published while nothing on the host forwarded them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<crate::netd::IngressBinding>,
}

/// The host interface netd created for a NIC, if any.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetdInterface {
    /// netd was not involved: user mode, custom mode, or a bridge NIC that
    /// QEMU's own bridge helper attaches.
    #[default]
    None,
    /// netd created the interface and bound no libvirt nwfilter to it.
    Unfiltered,
    /// netd created the interface and bound a libvirt nwfilter to it, which
    /// removal has to delete before the interface goes away.
    Filtered,
}

impl NetdInterface {
    pub fn is_none(&self) -> bool {
        matches!(self, NetdInterface::None)
    }

    pub fn is_filtered(&self) -> bool {
        matches!(self, NetdInterface::Filtered)
    }
}

impl Networking {
    pub fn is_bridge(&self) -> bool {
        self.nic.mode == NetworkingMode::Bridge
    }

    /// Whether the vhost-net data plane applies to this interface.
    ///
    /// Defaults to disabled: an upgraded node keeps the exact device shape its
    /// VMs booted with (one queue pair, userspace virtio) until the operator
    /// opts in, because `vhost = true` requires `/dev/vhost-net` to be
    /// accessible to the account QEMU runs under — a precondition the VMM
    /// cannot verify on the operator's behalf.
    pub fn vhost_enabled(&self) -> bool {
        self.nic.vhost.unwrap_or(false) && self.supports_vhost()
    }

    /// Whether the backend selected by `mode` can carry a vhost-net data plane
    /// at all. Custom mode is excluded because the operator supplies the whole
    /// netdev string, including any vhost options.
    pub fn supports_vhost(&self) -> bool {
        Self::mode_supports_vhost(self.nic.mode)
    }

    /// The same question about a mode on its own, for a caller deciding
    /// whether a request it has not built an entry for yet can be honoured.
    pub fn mode_supports_vhost(mode: NetworkingMode) -> bool {
        matches!(mode, NetworkingMode::Bridge | NetworkingMode::Macvtap)
    }

    /// Whether the backend selected by `mode` can carry more than one queue
    /// pair.
    ///
    /// Custom mode is excluded for the same reason as vhost: the operator
    /// supplies the whole netdev string and the VMM cannot edit it, so a
    /// multiqueue device line would have nothing to pair with. The RPC refuses
    /// such a request, but a node that switches its default to custom must not
    /// be able to produce one behind the RPC's back.
    pub fn supports_multiqueue(&self) -> bool {
        Self::mode_supports_multiqueue(self.nic.mode)
    }

    /// The same question about a mode on its own, for a caller deciding
    /// whether a request it has not built an entry for yet can be honoured.
    pub fn mode_supports_multiqueue(mode: NetworkingMode) -> bool {
        matches!(mode, NetworkingMode::Bridge | NetworkingMode::Macvtap)
    }

    /// Effective virtio-net queue pair count of a resolved NIC, never below
    /// one. Resolution makes the vCPU-scaled default concrete, so an entry that
    /// still carries none is read conservatively as single-queue.
    pub fn queue_pairs(&self) -> u32 {
        if !self.supports_multiqueue() {
            return 1;
        }
        self.nic.queues.unwrap_or(1).max(1)
    }

    /// Queue pairs a VM with this many vCPUs gets when it asks for none.
    ///
    /// The guest driver uses at most one queue pair per vCPU, so the default
    /// follows the vCPU count up to a fixed cap. A node that lowers
    /// `max_net_queues` below that cap means it, so the default follows it
    /// down; raising it above the cap only widens what a caller may request.
    pub fn default_queue_pairs(vcpu: u32, max_net_queues: u32) -> u32 {
        vcpu.clamp(1, DEFAULT_QUEUE_SCALING_CAP.min(max_net_queues).max(1))
    }

    /// Parse the mac_prefix into bytes. Returns 0-3 bytes.
    pub fn mac_prefix_bytes(&self) -> Vec<u8> {
        if self.mac_prefix.is_empty() {
            return vec![];
        }
        self.mac_prefix
            .split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .take(3)
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostApiConfig {
    pub address: String,
    pub port: u32,
}

impl HostApiConfig {
    /// Validate that the host API address is a vsock address.
    /// The host API must only listen on vsock for security reasons.
    /// TCP/Unix socket listening is not supported.
    pub fn validate(&self) -> Result<()> {
        let cid = self.address.strip_prefix("vsock:").with_context(|| {
            format!(
                "Host API address must be a vsock address (e.g., 'vsock:2'), got: '{}'. \
                 TCP/Unix socket listening is not supported for the host API.",
                self.address
            )
        })?;
        if let Some(cid) = cid.strip_prefix("0x") {
            u32::from_str_radix(cid, 16).context("Host API address contains an invalid CID")?;
        } else {
            cid.parse::<u32>()
                .context("Host API address contains an invalid CID")?;
        }
        anyhow::ensure!(self.port > 0, "Host API port must be greater than zero");
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyProviderConfig {
    pub enabled: bool,
    pub address: IpAddr,
    pub port: u16,
}

const CLIENT_CONF_PATH: &str = "/etc/dstack/client.conf";
fn read_qemu_path_from_client_conf() -> Option<PathBuf> {
    #[derive(Debug, Deserialize)]
    struct ClientQemuSection {
        path: Option<String>,
    }
    #[derive(Debug, Deserialize)]
    struct ClientIniConfig {
        qemu: Option<ClientQemuSection>,
    }

    let raw = fs_err::read_to_string(CLIENT_CONF_PATH).ok()?;
    let parsed: ClientIniConfig = serde_ini::from_str(&raw).ok()?;
    let path = parsed.qemu?.path?;
    let path = path.trim().trim_matches('"').trim_matches('\'');
    if path.is_empty() {
        return None;
    }
    let path = PathBuf::from(path);
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

impl Config {
    pub fn extract_or_default(figment: &Figment) -> Result<Self> {
        let mut me: Self = figment.extract()?;
        {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            let app_home = home.join(".dstack-vmm");
            // Migrate deprecated top-level `image_path` to `[image] path`
            if me.image_path != PathBuf::default() {
                if me.image.path == PathBuf::default() {
                    warn!(
                        "config: top-level `image_path` is deprecated, use `[image] path` instead"
                    );
                    me.image.path = me.image_path.clone();
                } else {
                    warn!("config: both `image_path` and `[image] path` are set, using `[image] path`");
                }
                me.image_path = PathBuf::default();
            }
            if me.image.path == PathBuf::default() {
                me.image.path = app_home.join("image");
            }
            if me.run_path == PathBuf::default() {
                me.run_path = app_home.join("vm");
            }
            if me.cvm.qemu_path == PathBuf::default() {
                // Prefer the path from dstack client config if present
                if let Some(qemu_path) = read_qemu_path_from_client_conf() {
                    info!("Found QEMU path from client config: {CLIENT_CONF_PATH:?}");
                    me.cvm.qemu_path = qemu_path;
                } else {
                    let cpu_arch = std::env::consts::ARCH;
                    let qemu_path = which::which(format!("qemu-system-{}", cpu_arch))
                        .context("Failed to find qemu executable")?;
                    me.cvm.qemu_path = qemu_path;
                }
            }
            info!("QEMU path: {}", me.cvm.qemu_path.display());

            // Detect QEMU version if not already set
            match &me.cvm.qemu_version {
                None => match detect_qemu_version(&me.cvm.qemu_path) {
                    Ok(version) => {
                        info!("Detected QEMU version: {version}");
                        me.cvm.qemu_version = Some(version);
                    }
                    Err(e) => {
                        warn!("Failed to detect QEMU version: {e}");
                        // Continue without version - the system will use defaults
                    }
                },
                Some(version) => info!("Configured QEMU version: {version}"),
            }
        }
        Ok(me)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_restart_config_rejects_hot_loop_and_inverted_backoff() {
        let mut config = AutoRestartConfig {
            enabled: true,
            interval: 0,
            max_retries: 3,
            initial_backoff: 2,
            max_backoff: 5,
            reset_window: 10,
        };
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("interval"));
        config.interval = 1;
        config.initial_backoff = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("initial_backoff"));
        config.initial_backoff = 6;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_backoff"));
        config.max_backoff = 6;
        assert!(config.validate().is_ok());

        config.enabled = false;
        config.interval = 0;
        config.initial_backoff = 7;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_qemu_version_debian_format() {
        let output = "QEMU emulator version 8.2.2 (Debian 2:8.2.2+ds-0ubuntu1.4+tdx1.0)\nCopyright (c) 2003-2023 Fabrice Bellard and the QEMU Project developers";
        let version = parse_qemu_version_from_output(output).unwrap();
        assert_eq!(version, "8.2.2");
    }

    #[test]
    fn test_parse_qemu_version_simple_format() {
        let output = "QEMU emulator version 9.1.0\nCopyright (c) 2003-2024 Fabrice Bellard and the QEMU Project developers";
        let version = parse_qemu_version_from_output(output).unwrap();
        assert_eq!(version, "9.1.0");
    }

    #[test]
    fn test_parse_qemu_version_old_debian_format() {
        let output = "QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.2)\nCopyright (c) 2003-2023 Fabrice Bellard and the QEMU Project developers";
        let version = parse_qemu_version_from_output(output).unwrap();
        assert_eq!(version, "8.2.2");
    }

    #[test]
    fn test_parse_qemu_version_with_rc() {
        let output = "QEMU emulator version 9.0.0-rc1\nCopyright (c) 2003-2024 Fabrice Bellard and the QEMU Project developers";
        let version = parse_qemu_version_from_output(output).unwrap();
        assert_eq!(version, "9.0.0-rc1");
    }

    #[test]
    fn test_parse_qemu_version_fallback() {
        let output = "Some unusual format 8.1.5 with version info";
        let version = parse_qemu_version_from_output(output).unwrap();
        assert_eq!(version, "8.1.5");
    }

    #[test]
    fn test_parse_qemu_version_invalid() {
        let output = "No version information here";
        let result = parse_qemu_version_from_output(output);
        assert!(result.is_err());
    }

    #[test]
    fn tee_platform_deserializes_amd_sev_snp() {
        let platform: CvmPlatform = serde_json::from_str("\"amd-sev-snp\"").unwrap();
        assert_eq!(platform, CvmPlatform::AmdSevSnp);
    }

    #[test]
    fn platform_config_maps_auto_and_omitted_to_none() {
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_platform")]
            platform: Option<CvmPlatform>,
        }
        let parse = |s: &str| serde_json::from_str::<Wrap>(s).unwrap().platform;
        // Omitted and the legacy `auto` literal both mean "auto-detect" (None).
        assert_eq!(parse("{}"), None);
        assert_eq!(parse(r#"{"platform":"auto"}"#), None);
        // Explicit platforms are pinned.
        assert_eq!(parse(r#"{"platform":"tdx"}"#), Some(CvmPlatform::Tdx));
        assert_eq!(
            parse(r#"{"platform":"amd-sev-snp"}"#),
            Some(CvmPlatform::AmdSevSnp)
        );
    }

    #[test]
    fn tdx_attestation_variant_config_accepts_auto_and_resolves() {
        let parse = |s: &str| serde_json::from_str::<TdxAttestationVariantConfig>(s).unwrap();
        assert_eq!(parse(r#""legacy""#), TdxAttestationVariantConfig::Legacy);
        assert_eq!(parse(r#""lite""#), TdxAttestationVariantConfig::Lite);
        assert_eq!(parse(r#""auto""#), TdxAttestationVariantConfig::Auto);

        use dstack_types::TdxAttestationVariant::{Legacy, Lite};

        // Explicit settings bypass auto heuristics.
        assert_eq!(
            TdxAttestationVariantConfig::Legacy.resolve(2048, true),
            Legacy
        );
        assert_eq!(TdxAttestationVariantConfig::Lite.resolve(1024, false), Lite);

        // Auto avoids lite for sub-3 GiB memory sizes except exactly 2 GiB.
        assert_eq!(
            TdxAttestationVariantConfig::Auto.resolve(1024, true),
            Legacy
        );
        assert_eq!(
            TdxAttestationVariantConfig::Auto.resolve(2816, true),
            Legacy
        );
        assert_eq!(TdxAttestationVariantConfig::Auto.resolve(2048, true), Lite);

        // At 3 GiB and above, auto follows image support.
        assert_eq!(TdxAttestationVariantConfig::Auto.resolve(3072, true), Lite);
        assert_eq!(
            TdxAttestationVariantConfig::Auto.resolve(3072, false),
            Legacy
        );
    }

    fn default_config() -> Config {
        use rocket::figment::providers::{Format, Toml};

        Figment::from(Toml::string(DEFAULT_CONFIG))
            .extract()
            .expect("default VMM config should parse")
    }

    /// The two ownership markers are additive on disk: manifests and runtime
    /// network snapshots written before they existed still load, and an entry
    /// that carries neither serializes exactly as it used to.
    #[test]
    fn ownership_markers_are_omitted_when_unset_and_default_when_absent() {
        let mut networking: Networking =
            serde_json::from_str(r#"{"mode":"bridge","bridge":"br0"}"#).unwrap();
        assert!(!networking.nic.inherit_mode);
        assert_eq!(networking.netd_interface, NetdInterface::None);

        let json = serde_json::to_string(&networking).unwrap();
        assert!(!json.contains("inherit_mode"), "{json}");
        assert!(!json.contains("netd_interface"), "{json}");

        networking.nic.inherit_mode = true;
        networking.netd_interface = NetdInterface::Filtered;
        let json = serde_json::to_string(&networking).unwrap();
        assert!(json.contains(r#""inherit_mode":true"#), "{json}");
        assert!(json.contains(r#""netd_interface":"filtered""#), "{json}");
        assert_eq!(
            serde_json::from_str::<Networking>(&json).unwrap(),
            networking
        );
    }

    #[test]
    fn config_validation_accepts_defaults() {
        let config = default_config();
        assert_eq!(config.netd.socket_mode, 0o660);
        assert!(config.cvm.shuffle_kms_urls);
        assert!(config.cvm.shuffle_gateway_urls);
        config.validate().unwrap();
    }

    #[test]
    fn config_validation_rejects_invalid_static_invariants() {
        let mut config = default_config();
        config.netd.socket_mode = 0o1660;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("socket_mode"));

        let mut config = default_config();
        config.cvm.cid_pool_size = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cid_pool_size"));

        let mut config = default_config();
        config.cvm.port_mapping.range[0].from = 200;
        config.cvm.port_mapping.range[0].to = 100;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("range start"));

        // An empty filter tells netd to create an unfiltered TAP, so libvirt
        // mode must never carry one.
        let mut config = default_config();
        config.cvm.network_filter.mode = NetworkFilterMode::Libvirt;
        config.cvm.network_filter.filter = String::new();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("network_filter.filter"));

        let mut config = default_config();
        config.cvm.max_net_queues = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_net_queues"));

        let mut config = default_config();
        config.cvm.max_net_queues = MAX_NET_QUEUES + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_net_queues"));

        // The node-wide value is gone; say so rather than ignoring it.
        let mut config = default_config();
        config.cvm.networking.nic.queues = Some(4);
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cvm.networking.queues is not a node setting"));

        let mut config = default_config();
        config.cvm.networking.mac_prefix = "02:not-hex".into();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("mac_prefix"));

        let mut config = default_config();
        config.cvm.host_share_mode = "unknown".into();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("host_share_mode"));
    }

    #[test]
    fn config_validation_rejects_invalid_endpoints() {
        let mut config = default_config();
        config.cvm.kms_urls = vec!["not a URL".into()];
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("kms_urls"));

        let mut config = default_config();
        config.supervisor.sock.clear();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("supervisor.sock"));

        let mut config = default_config();
        config.cvm.networking.nic.mode = NetworkingMode::Bridge;
        config.cvm.networking.nic.bridge.clear();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("networking.bridge"));

        let mut config = default_config();
        config.host_api.address = "vsock:not-a-cid".into();
        assert!(format!("{:#}", config.validate().unwrap_err()).contains("invalid CID"));
    }

    #[test]
    fn config_validation_rejects_mixed_gateway_syntax() {
        let mut config = default_config();
        config.cvm.gateway_urls = vec!["https://legacy-gateway.example.com".into()];
        config.cvm.gateway_clusters = vec![dstack_types::GatewayClusterConfig {
            name: "primary".into(),
            urls: vec!["https://gateway.example.com".into()],
        }];
        let error = config.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("gateway_urls and cvm.gateway_clusters cannot both"));
    }

    #[test]
    fn config_validation_does_not_require_supervisor_startup_paths_when_disabled() {
        let mut config = default_config();
        config.supervisor.auto_start = false;
        config.supervisor.exe.clear();
        config.supervisor.pid_file.clear();
        config.supervisor.log_file.clear();
        config.validate().unwrap();
    }

    #[test]
    fn tee_platform_auto_detects_amd_sev_snp_from_flag() {
        let cpuinfo = "flags : fpu svm sev sev_es sev_snp debug_swap";
        assert_eq!(
            CvmPlatform::resolve_from_cpuinfo(cpuinfo),
            CvmPlatform::AmdSevSnp
        );
    }

    #[test]
    fn tee_platform_auto_detects_tdx_host() {
        let cpuinfo = "flags : fpu vmx tdx_host_platform";
        assert_eq!(CvmPlatform::resolve_from_cpuinfo(cpuinfo), CvmPlatform::Tdx);
    }

    #[test]
    fn tee_platform_auto_falls_back_to_tdx_without_tee_flag() {
        let cpuinfo = "flags : fpu vmx";
        assert_eq!(CvmPlatform::resolve_from_cpuinfo(cpuinfo), CvmPlatform::Tdx);
    }
}

#[cfg(test)]
mod networking_shape_tests {
    use super::{Config, Networking, NetworkingMode, NicNetworking, DEFAULT_CONFIG};

    /// Splitting the type must not split the wire format. `[cvm.networking]`
    /// is flattened, so a node config, a stored manifest and a runtime-networks
    /// snapshot written by an earlier build all still parse, and what this
    /// build writes is byte-for-byte what the old one did.
    #[test]
    fn the_split_types_keep_one_flat_serialized_shape() {
        let legacy = serde_json::json!({
            "mode": "bridge",
            "bridge": "br0",
            "parent": "eth0",
            "macvtap_mode": "private",
            "device": "/dev/tap7",
            "mac_prefix": "02:aa:bb",
            "net": "10.0.2.0/24",
            "dhcp_start": "10.0.2.15",
            "restrict": true,
            "netdev": "",
            "vhost": false,
            "queues": 4,
            "inherit_mode": true,
            "netd_interface": "filtered",
        });

        // A resolved value keeps every field, at the same names as before.
        let resolved: Networking = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(resolved.nic.mode, NetworkingMode::Bridge);
        assert_eq!(resolved.nic.bridge, "br0");
        assert_eq!(resolved.nic.queues, Some(4));
        assert!(resolved.nic.inherit_mode);
        assert_eq!(resolved.macvtap_mode, "private");
        assert_eq!(resolved.net, "10.0.2.0/24");
        assert!(resolved.restrict);
        let round_tripped = serde_json::to_value(&resolved).unwrap();
        assert_eq!(round_tripped["mode"], "bridge");
        assert_eq!(round_tripped["macvtap_mode"], "private");
        assert_eq!(round_tripped["queues"], 4);

        // A manifest entry written by a build that stored the whole thing
        // still loads; the node's half is simply dropped on the way in.
        let pinned: NicNetworking = serde_json::from_value(legacy).unwrap();
        assert_eq!(pinned.bridge, "br0");
        assert_eq!(pinned.parent, "eth0");
        assert_eq!(pinned.vhost, Some(false));
        let stored = serde_json::to_value(&pinned).unwrap();
        assert_eq!(stored.as_object().unwrap().len(), 6);
        assert!(stored.get("macvtap_mode").is_none());
        assert!(stored.get("net").is_none());
    }

    /// The TOML section still deserializes through the flatten.
    #[test]
    fn the_node_section_still_parses_from_toml() {
        use rocket::figment::providers::Format as _;
        let config: Config = rocket::figment::Figment::from(
            rocket::figment::providers::Toml::string(DEFAULT_CONFIG),
        )
        .extract()
        .unwrap();
        assert_eq!(config.cvm.networking.nic.mode, NetworkingMode::User);
    }
}
