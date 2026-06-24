// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! render the config files `dstackup install` writes.
//!
//! Two are produced here:
//! * `kms.toml` — embedded into the KMS-in-CVM app-compose; this is the
//!   single-node Tier-1 config (webhook auth + `enforce_self_authorization =
//!   false` + a set `auto_bootstrap_domain`, the combination validated to make
//!   bootstrap hands-off — see docs/onboarding-redesign.md §5).
//! * `auth-allowlist.json` — read by the host-side Rust auth webhook.
//!
//! `vmm.toml` rendering is a follow-up.

use anyhow::{Context, Result};
use serde_json::json;
use std::path::Path;

/// normalize a hex string for comparison: trim, drop a single `0x`/`0X`
/// prefix, lowercase. MUST stay in sync with `dstack-auth`'s `norm()` — the
/// webhook compares allowlist entries against KMS-supplied hashes with the same
/// rule, so a divergence here silently denies (or wrongly allows) apps.
pub fn norm_hex(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.to_lowercase()
}

/// register an app (id + compose hash) in the auth webhook's allowlist file,
/// so the KMS will issue keys to it. Read-modify-write; idempotent.
///
/// Holds an exclusive lock for the whole read-modify-write (so two concurrent
/// `dstack run`s can't clobber each other) and writes atomically (so a crash or
/// partial write can't leave torn JSON — which the webhook would read as
/// deny-all). The stored hash is normalized so the on-disk file can't
/// accumulate visually-distinct-but-equal entries.
pub fn register_app_in_allowlist(path: &Path, app_id: &str, compose_hash: &str) -> Result<()> {
    let _lock = crate::fsutil::lock_exclusive(path)?;
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
            "allowlist {} does not exist — run `dstackup install` first, or check the --allowlist path",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(e).with_context(|| {
                format!(
                    "reading allowlist {} (it is usually root-owned — run with sudo)",
                    path.display()
                )
            })
        }
        Err(e) => return Err(e).with_context(|| format!("reading allowlist {}", path.display())),
    };
    let mut v: serde_json::Value = serde_json::from_str(&body).context("parsing allowlist json")?;
    let apps = v
        .get_mut("apps")
        .and_then(|a| a.as_object_mut())
        .context("allowlist has no `apps` object")?;
    let entry = apps
        .entry(norm_hex(app_id))
        .or_insert_with(|| json!({ "composeHashes": [], "devices": [], "allowAnyDevice": true }));
    let hashes = entry
        .get_mut("composeHashes")
        .and_then(|h| h.as_array_mut())
        .context("app entry missing `composeHashes`")?;
    let norm = norm_hex(compose_hash);
    let present = hashes
        .iter()
        .any(|h| h.as_str().map(|s| norm_hex(s) == norm).unwrap_or(false));
    if !present {
        hashes.push(serde_json::Value::String(norm));
    }
    crate::fsutil::write_atomic(path, &serde_json::to_string_pretty(&v)?)
        .with_context(|| format!("writing allowlist {}", path.display()))?;
    Ok(())
}

/// public OS-image download URL template used by the KMS image-hash verifier.
pub const DEFAULT_IMAGE_DOWNLOAD_URL: &str =
    "https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz";

/// inputs that parameterize the rendered configs.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// URL the KMS-in-CVM uses to reach the host auth webhook
    /// (the host as seen from the CVM under user-mode networking, e.g.
    /// `http://10.0.2.2:8001`).
    pub auth_webhook_url: String,
    /// KMS bootstrap domain — the host address as seen from the CVM
    /// (e.g. `10.0.2.2`); the bootstrapped RPC cert is issued for this.
    pub kms_bootstrap_domain: String,
    /// OS image hash to allow apps to boot from (the measured guest image).
    pub os_image_hash: String,
    /// OS image download URL template (must contain `{OS_IMAGE_HASH}`).
    pub image_download_url: String,
    /// whether the KMS verifies the OS image hash on app key requests.
    pub verify_os_image: bool,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            auth_webhook_url: "http://10.0.2.2:8001".to_string(),
            kms_bootstrap_domain: "10.0.2.2".to_string(),
            os_image_hash: String::new(),
            image_download_url: DEFAULT_IMAGE_DOWNLOAD_URL.to_string(),
            verify_os_image: true,
        }
    }
}

/// render the single-node KMS config (lives at `/kms/kms.toml` inside the CVM).
pub fn kms_toml(cfg: &HostConfig) -> String {
    format!(
        r#"# generated by `dstackup install` — single-node Tier-1 KMS

[rpc]
address = "0.0.0.0"
port = 8000

[rpc.tls]
key = "/kms/certs/rpc.key"
certs = "/kms/certs/rpc.crt"

[rpc.tls.mutual]
ca_certs = "/kms/certs/tmp-ca.crt"
mandatory = false

[core]
cert_dir = "/kms/certs"
admin_token_hash = ""
# single-node: the KMS does not self-attest to its own auth API before
# bootstrap (it still attests the genesis keys via the guest agent, and app
# auth + per-app quote checks are unaffected). See onboarding-redesign.md §5.
enforce_self_authorization = false

[core.image]
verify = {verify}
cache_dir = "/kms/images"
download_url = "{download_url}"
download_timeout = "2m"

[core.metrics]
enabled = false

[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "{webhook_url}"

[core.onboard]
enabled = true
auto_bootstrap_domain = "{bootstrap_domain}"
address = "0.0.0.0"
port = 8000
"#,
        verify = cfg.verify_os_image,
        download_url = cfg.image_download_url,
        webhook_url = cfg.auth_webhook_url,
        bootstrap_domain = cfg.kms_bootstrap_domain,
    )
}

/// render the host-side auth webhook allowlist.
///
/// Tier-1 single-node: the OS image is allowed, the KMS `mrAggregated` allowlist
/// is empty (no replication; self-bootstrap is hands-off), and per-app compose
/// hashes are added by `dstack run`.
pub fn auth_allowlist_json(cfg: &HostConfig) -> String {
    let allowlist = json!({
        "osImages": if cfg.os_image_hash.is_empty() {
            Vec::<String>::new()
        } else {
            vec![cfg.os_image_hash.clone()]
        },
        "kms": {
            "mrAggregated": [],
            "devices": [],
            "allowAnyDevice": true
        },
        "apps": {}
    });
    // infallible pretty-print via Value's Display; see compose::build_app_compose.
    format!("{allowlist:#}")
}

/// default pinned, reproducibly-built KMS image (Docker Hub).
pub const DEFAULT_KMS_IMAGE: &str = "dstacktee/dstack-kms:0.5.11";

/// build the KMS-in-CVM app-compose manifest. The CVM runs in
/// local-key-provider mode; an init script writes the rendered `kms.toml` into
/// the guest, and the KMS container mounts it.
pub fn kms_app_compose(kms_toml: &str, kms_image: &str) -> String {
    let docker_compose = format!(
        r#"services:
  kms:
    image: {kms_image}
    volumes:
      - kms-volume:/kms
      - /var/run/dstack.sock:/var/run/dstack.sock
      - /dstack/kms-config/kms.toml:/kms/kms.toml:ro
    ports:
      - "8000:8000"
    restart: unless-stopped
    command: sh -c 'mkdir -p /kms/certs /kms/images && exec dstack-kms -c /kms/kms.toml'
volumes:
  kms-volume:
"#
    );
    let init_script = format!(
        "mkdir -p /dstack/kms-config\ncat > /dstack/kms-config/kms.toml <<'KMSTOML'\n{kms_toml}\nKMSTOML\ntrue\n"
    );
    let manifest = json!({
        "manifest_version": 2,
        "name": "dstack-kms",
        "runner": "docker-compose",
        "docker_compose_file": docker_compose,
        "init_script": init_script,
        "kms_enabled": false,
        "gateway_enabled": false,
        "local_key_provider_enabled": true,
        "public_logs": true,
        "public_sysinfo": true,
        "public_tcbinfo": true,
        "no_instance_id": false,
        "secure_time": false,
        "allowed_envs": []
    });
    // infallible pretty-print via Value's Display; see compose::build_app_compose.
    format!("{manifest:#}")
}

/// inputs for rendering `vmm.toml`. Defaults target a localhost dashboard and
/// reuse of an existing local key provider; the isolation knobs (ports, cid
/// range, prefix) let a fresh instance coexist with an existing VMM.
#[derive(Debug, Clone)]
pub struct VmmRender {
    /// Rocket endpoint for the dashboard + management API
    /// (e.g. `tcp:127.0.0.1:9080`, or `unix:<path>`).
    pub dashboard_addr: String,
    /// guest image directory.
    pub image_path: String,
    /// qemu binary path.
    pub qemu_path: String,
    /// run directory for the supervisor socket/pid/log.
    pub run_dir: String,
    /// VM storage directory (isolated per install; default `~/.dstack-vmm/vm`).
    pub vm_path: String,
    /// supervisor binary path.
    pub supervisor_exe: String,
    /// CID pool start (raise to coexist with an existing VMM).
    pub cid_start: u32,
    /// CID pool size.
    pub cid_pool_size: u32,
    /// host-api vsock port (raise to coexist with an existing VMM on 10000).
    pub host_api_port: u32,
    /// local key-provider address (reuse the running one).
    pub key_provider_addr: String,
    /// local key-provider port.
    pub key_provider_port: u32,
    /// KMS URLs injected into app CVMs (the guest-visible KMS address).
    pub kms_urls: Vec<String>,
}

impl Default for VmmRender {
    fn default() -> Self {
        Self {
            dashboard_addr: "tcp:127.0.0.1:9080".to_string(),
            image_path: "/var/lib/dstack/images".to_string(),
            qemu_path: "/usr/bin/qemu-system-x86_64".to_string(),
            run_dir: "/var/lib/dstack/run".to_string(),
            vm_path: "/var/lib/dstack/vm".to_string(),
            supervisor_exe: "/usr/bin/dstack-supervisor".to_string(),
            cid_start: 1000,
            cid_pool_size: 1000,
            host_api_port: 10000,
            key_provider_addr: "127.0.0.1".to_string(),
            key_provider_port: 3443,
            kms_urls: Vec::new(),
        }
    }
}

/// render the host `vmm.toml`. Gateway and auth-token gating are off (Tier-1
/// direct-port access); CVMs use user-mode networking with host port mapping.
pub fn vmm_toml(r: &VmmRender) -> String {
    format!(
        r#"# generated by `dstackup install`

workers = 8
max_blocking = 64
ident = "dstack VMM"
temp_dir = "/tmp"
keep_alive = 10
log_level = "info"
address = "{dashboard_addr}"
reuse = true
kms_url = ""
event_buffer_size = 20
node_name = ""
run_path = "{vm_path}"

[image]
path = "{image_path}"
registry = ""

[cvm]
qemu_path = "{qemu_path}"
kms_urls = [{kms_urls}]
gateway_urls = []
pccs_url = ""
docker_registry = ""
cid_start = {cid_start}
cid_pool_size = {cid_pool_size}
max_allocable_vcpu = 20
max_allocable_memory_in_mb = 100_000
qmp_socket = false
user = ""
use_mrconfigid = false
qemu_pci_hole64_size = 0
qemu_hotplug_off = false
host_share_mode = "9p"
qgs_port = 4050

[cvm.product]
sys_vendor = "dstack"
product_name = "dstack"

[cvm.networking]
mode = "user"
net = "10.0.2.0/24"
dhcp_start = "10.0.2.10"
restrict = false
forward_service_enabled = false

[cvm.port_mapping]
enabled = true
address = "127.0.0.1"
range = [
    {{ protocol = "tcp", from = 1, to = 20000 }},
]

[cvm.auto_restart]
enabled = true
interval = 20

[cvm.gpu]
enabled = false
listing = []
exclude = []
include = []
allow_attach_all = false

[gateway]
base_domain = "localhost"
port = 8082
agent_port = 8090

[auth]
enabled = false
tokens = []

[supervisor]
exe = "{supervisor_exe}"
sock = "{run_dir}/supervisor.sock"
pid_file = "{run_dir}/supervisor.pid"
log_file = "{run_dir}/supervisor.log"
detached = true
auto_start = true

[host_api]
ident = "dstack VMM"
address = "vsock:2"
port = {host_api_port}

[key_provider]
enabled = true
address = "{kp_addr}"
port = {kp_port}
"#,
        dashboard_addr = r.dashboard_addr,
        image_path = r.image_path,
        vm_path = r.vm_path,
        qemu_path = r.qemu_path,
        kms_urls = r
            .kms_urls
            .iter()
            .map(|u| format!("\"{u}\""))
            .collect::<Vec<_>>()
            .join(", "),
        cid_start = r.cid_start,
        cid_pool_size = r.cid_pool_size,
        supervisor_exe = r.supervisor_exe,
        run_dir = r.run_dir,
        host_api_port = r.host_api_port,
        kp_addr = r.key_provider_addr,
        kp_port = r.key_provider_port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmm_toml_is_valid_and_parameterized() {
        let r = VmmRender {
            dashboard_addr: "tcp:127.0.0.1:19080".into(),
            cid_start: 2000,
            host_api_port: 10001,
            ..Default::default()
        };
        let rendered = vmm_toml(&r);
        assert!(rendered.contains(r#"address = "tcp:127.0.0.1:19080""#));
        assert!(rendered.contains("cid_start = 2000"));
        assert!(rendered.contains("port = 10001"));
        toml::from_str::<toml::Value>(&rendered).expect("vmm.toml must be valid TOML");
    }

    #[test]
    fn kms_toml_has_tier1_invariants() {
        let cfg = HostConfig {
            auth_webhook_url: "http://10.0.2.2:8001".into(),
            kms_bootstrap_domain: "10.0.2.2".into(),
            ..Default::default()
        };
        let toml = kms_toml(&cfg);
        assert!(toml.contains("enforce_self_authorization = false"));
        assert!(toml.contains(r#"auto_bootstrap_domain = "10.0.2.2""#));
        assert!(toml.contains(r#"type = "webhook""#));
        assert!(toml.contains(r#"url = "http://10.0.2.2:8001""#));
        // sanity: it parses as TOML.
        toml::from_str::<toml::Value>(&toml).expect("kms.toml must be valid TOML");
    }

    #[test]
    fn allowlist_shape() {
        let cfg = HostConfig {
            os_image_hash: "0xabc".into(),
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::from_str(&auth_allowlist_json(&cfg)).unwrap();
        assert_eq!(v["osImages"][0], "0xabc");
        assert_eq!(v["kms"]["mrAggregated"].as_array().unwrap().len(), 0);
        assert!(v["apps"].as_object().unwrap().is_empty());
    }
}
