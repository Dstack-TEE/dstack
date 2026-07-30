// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Least-privilege host networking backend for protected bridge NICs.

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream as StdUnixStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use nix::unistd::{chown, Gid, User};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader},
    net::{UnixListener, UnixStream},
};

use crate::{
    app::validate_resolved_network,
    config::{CvmConfig, Networking, NetworkingMode},
};

const MAX_REQUEST_BYTES: usize = 4096;
const NFT_TABLE_PREFIX: &str = "dstack_";
const TAP_ALIAS_PREFIX: &str = "dstack-vmm:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NicAttachment {
    pub vm_id: String,
    pub nic_index: usize,
    pub bridge: String,
    pub tap: String,
    pub mac: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request {
    Prepare {
        vm_id: String,
        nic_index: usize,
        bridge: String,
        mac: String,
    },
    Remove {
        attachment: NicAttachment,
    },
    Check {
        attachment: NicAttachment,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    ok: bool,
    attachment: Option<NicAttachment>,
    error: Option<String>,
}

impl Response {
    fn success(attachment: Option<NicAttachment>) -> Self {
        Self {
            ok: true,
            attachment,
            error: None,
        }
    }

    fn error(error: impl ToString) -> Self {
        Self {
            ok: false,
            attachment: None,
            error: Some(error.to_string()),
        }
    }

    fn into_result(self) -> Result<Option<NicAttachment>> {
        if self.ok {
            Ok(self.attachment)
        } else {
            bail!(self.error.unwrap_or_else(|| "dstack-netd failed".into()))
        }
    }
}

#[derive(Clone)]
pub(crate) struct Client {
    socket: PathBuf,
}

impl Client {
    pub(crate) fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub(crate) async fn prepare(
        &self,
        vm_id: &str,
        nic_index: usize,
        bridge: &str,
        mac: &str,
    ) -> Result<NicAttachment> {
        let response = self
            .request(&Request::Prepare {
                vm_id: vm_id.to_string(),
                nic_index,
                bridge: bridge.to_string(),
                mac: mac.to_string(),
            })
            .await?;
        response.context("dstack-netd returned no attachment")
    }

    pub(crate) async fn remove(&self, attachment: &NicAttachment) -> Result<()> {
        self.request(&Request::Remove {
            attachment: attachment.clone(),
        })
        .await?;
        Ok(())
    }

    pub(crate) async fn check(&self, attachment: &NicAttachment) -> Result<()> {
        self.request(&Request::Check {
            attachment: attachment.clone(),
        })
        .await?;
        Ok(())
    }

    async fn request(&self, request: &Request) -> Result<Option<NicAttachment>> {
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("failed to connect to {}", self.socket.display()))?;
        let mut encoded = serde_json::to_vec(request)?;
        if encoded.len() > MAX_REQUEST_BYTES {
            bail!("dstack-netd request is too large");
        }
        encoded.push(b'\n');
        stream.write_all(&encoded).await?;
        stream.shutdown().await?;

        let mut response = String::new();
        AsyncBufReader::new(stream)
            .read_line(&mut response)
            .await
            .context("failed to read dstack-netd response")?;
        serde_json::from_str::<Response>(&response)
            .context("invalid dstack-netd response")?
            .into_result()
    }
}

pub(crate) async fn serve(cfg: CvmConfig) -> Result<()> {
    let socket = &cfg.networking.netd_socket;
    if socket.as_os_str().is_empty() {
        bail!("cvm.networking.netd_socket must not be empty");
    }
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if socket.exists() {
        fs::remove_file(socket)
            .with_context(|| format!("failed to remove stale {}", socket.display()))?;
    }
    let listener = UnixListener::bind(socket)
        .with_context(|| format!("failed to bind {}", socket.display()))?;
    if let Some(gid) = cfg.networking.netd_socket_gid {
        chown(socket, None, Some(Gid::from_raw(gid)))?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o660))?;
    } else {
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    }

    let server = std::sync::Arc::new(Server::new(cfg)?);
    loop {
        let (stream, _) = listener.accept().await?;
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, server).await {
                tracing::warn!(%error, "dstack-netd request failed");
            }
        });
    }
}

async fn handle_connection(stream: UnixStream, server: std::sync::Arc<Server>) -> Result<()> {
    let credentials = stream
        .peer_cred()
        .context("failed to read peer credentials")?;
    if !server.allowed_uids.contains(&credentials.uid()) {
        bail!(
            "uid {} is not authorized for dstack-netd",
            credentials.uid()
        );
    }

    let (reader, mut writer) = stream.into_split();
    let mut request = Vec::new();
    AsyncBufReader::new(reader)
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_until(b'\n', &mut request)
        .await?;
    if request.is_empty() || request.len() > MAX_REQUEST_BYTES || !request.ends_with(b"\n") {
        bail!("invalid dstack-netd request framing");
    }

    let parsed = serde_json::from_slice::<Request>(&request);
    let response = match parsed {
        Ok(request) => {
            let server = server.clone();
            match tokio::task::spawn_blocking(move || server.handle(request)).await {
                Ok(Ok(attachment)) => Response::success(attachment),
                Ok(Err(error)) => Response::error(format!("{error:#}")),
                Err(error) => Response::error(format!("network worker failed: {error}")),
            }
        }
        Err(error) => Response::error(format!("invalid request: {error}")),
    };
    let mut encoded = serde_json::to_vec(&response)?;
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.shutdown().await?;
    Ok(())
}

struct Server {
    cfg: CvmConfig,
    qemu_uid: u32,
    allowed_uids: Vec<u32>,
}

impl Server {
    fn new(cfg: CvmConfig) -> Result<Self> {
        let qemu_uid = if cfg.user.is_empty() {
            0
        } else {
            User::from_name(&cfg.user)
                .context("failed to resolve QEMU user")?
                .with_context(|| format!("QEMU user '{}' does not exist", cfg.user))?
                .uid
                .as_raw()
        };
        let allowed_uids = if cfg.networking.netd_allowed_uids.is_empty() {
            vec![0]
        } else {
            cfg.networking.netd_allowed_uids.clone()
        };
        Ok(Self {
            cfg,
            qemu_uid,
            allowed_uids,
        })
    }

    fn handle(&self, request: Request) -> Result<Option<NicAttachment>> {
        match request {
            Request::Prepare {
                vm_id,
                nic_index,
                bridge,
                mac,
            } => self.prepare(&vm_id, nic_index, &bridge, &mac).map(Some),
            Request::Remove { attachment } => {
                self.validate_attachment(&attachment)?;
                self.remove_owned(&attachment)?;
                Ok(None)
            }
            Request::Check { attachment } => {
                self.validate_attachment(&attachment)?;
                self.check(&attachment)?;
                Ok(None)
            }
        }
    }

    fn prepare(
        &self,
        vm_id: &str,
        nic_index: usize,
        bridge: &str,
        mac: &str,
    ) -> Result<NicAttachment> {
        validate_vm_id(vm_id)?;
        validate_mac(mac)?;
        let mut networking = self.cfg.networking.clone();
        networking.mode = NetworkingMode::Bridge;
        networking.bridge = bridge.to_string();
        validate_resolved_network(&networking, &self.cfg.networking)?;

        let attachment = NicAttachment {
            vm_id: vm_id.to_string(),
            nic_index,
            bridge: bridge.to_string(),
            tap: tap_name(vm_id, nic_index)?,
            mac: mac.to_ascii_lowercase(),
        };
        self.validate_attachment(&attachment)?;

        if Path::new("/sys/class/net").join(&attachment.tap).exists() {
            self.verify_alias(&attachment)?;
            self.remove_owned(&attachment)?;
        }

        let result = self.create(&attachment);
        if result.is_err() {
            let _ = self.remove_owned(&attachment);
        }
        result.map(|()| attachment)
    }

    fn create(&self, attachment: &NicAttachment) -> Result<()> {
        let qemu_uid = self.qemu_uid.to_string();
        run(
            "ip",
            &[
                "tuntap",
                "add",
                "dev",
                &attachment.tap,
                "mode",
                "tap",
                "user",
                &qemu_uid,
                "vnet_hdr",
            ],
        )?;
        run(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &attachment.tap,
                "alias",
                &tap_alias(attachment),
            ],
        )?;
        run(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &attachment.tap,
                "master",
                &attachment.bridge,
            ],
        )?;
        let mut bridge_args = vec![
            "link",
            "set",
            "dev",
            &attachment.tap,
            "learning",
            "off",
            "locked",
            "on",
            "guard",
            "on",
            "root_block",
            "on",
        ];
        if self.cfg.networking.isolate_bridge_ports {
            bridge_args.extend(["isolated", "on"]);
        }
        run("bridge", &bridge_args)?;
        run(
            "bridge",
            &[
                "fdb",
                "replace",
                &attachment.mac,
                "dev",
                &attachment.tap,
                "master",
                "static",
            ],
        )?;
        run_with_stdin("nft", &["-f", "-"], &nft_rules(attachment))?;
        run("ip", &["link", "set", "dev", &attachment.tap, "up"])?;
        Ok(())
    }

    fn remove_owned(&self, attachment: &NicAttachment) -> Result<()> {
        let path = Path::new("/sys/class/net").join(&attachment.tap);
        if path.exists() {
            self.verify_alias(attachment)?;
            let _ = run("ip", &["link", "set", "dev", &attachment.tap, "down"]);
            let _ = run("ip", &["link", "set", "dev", &attachment.tap, "nomaster"]);
        }
        let _ = run(
            "nft",
            &["delete", "table", "netdev", &nft_table_name(attachment)],
        );
        if path.exists() {
            run("ip", &["link", "delete", "dev", &attachment.tap])?;
        }
        Ok(())
    }

    fn check(&self, attachment: &NicAttachment) -> Result<()> {
        self.verify_alias(attachment)?;
        let master = fs::canonicalize(
            Path::new("/sys/class/net")
                .join(&attachment.tap)
                .join("master"),
        )
        .context("protected TAP has no bridge master")?;
        if master.file_name().and_then(|name| name.to_str()) != Some(&attachment.bridge) {
            bail!("protected TAP is attached to an unexpected bridge");
        }
        run(
            "nft",
            &["list", "table", "netdev", &nft_table_name(attachment)],
        )?;
        Ok(())
    }

    fn validate_attachment(&self, attachment: &NicAttachment) -> Result<()> {
        validate_vm_id(&attachment.vm_id)?;
        validate_mac(&attachment.mac)?;
        if attachment.tap != tap_name(&attachment.vm_id, attachment.nic_index)? {
            bail!("attachment TAP name does not match its VM identity");
        }
        let mut networking = self.cfg.networking.clone();
        networking.mode = NetworkingMode::Bridge;
        networking.bridge = attachment.bridge.clone();
        validate_resolved_network(&networking, &self.cfg.networking)
    }

    fn verify_alias(&self, attachment: &NicAttachment) -> Result<()> {
        let alias_path = Path::new("/sys/class/net")
            .join(&attachment.tap)
            .join("ifalias");
        let alias = fs::read_to_string(&alias_path)
            .with_context(|| format!("failed to read {}", alias_path.display()))?;
        if alias.trim() != tap_alias(attachment) {
            bail!("refusing to modify foreign interface '{}'", attachment.tap);
        }
        Ok(())
    }
}

fn validate_vm_id(vm_id: &str) -> Result<()> {
    if vm_id.is_empty()
        || vm_id.len() > 128
        || !vm_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        bail!("invalid VM ID");
    }
    Ok(())
}

fn validate_mac(mac: &str) -> Result<()> {
    let bytes = mac
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid MAC address")?;
    if bytes.len() != 6 || bytes[0] & 1 != 0 || bytes.iter().all(|byte| *byte == 0) {
        bail!("invalid unicast MAC address");
    }
    Ok(())
}

fn tap_name(vm_id: &str, nic_index: usize) -> Result<String> {
    validate_vm_id(vm_id)?;
    if nic_index > 99 {
        bail!("NIC index exceeds the deterministic TAP naming range");
    }
    let digest = hex::encode(Sha256::digest(vm_id.as_bytes()));
    Ok(format!("dst{}n{nic_index}", &digest[..8]))
}

fn tap_alias(attachment: &NicAttachment) -> String {
    format!(
        "{TAP_ALIAS_PREFIX}{}:{}:{}",
        attachment.vm_id, attachment.nic_index, attachment.mac
    )
}

fn nft_table_name(attachment: &NicAttachment) -> String {
    let digest = hex::encode(Sha256::digest(attachment.vm_id.as_bytes()));
    format!(
        "{NFT_TABLE_PREFIX}{}_{}",
        &digest[..8],
        attachment.nic_index
    )
}

fn nft_rules(attachment: &NicAttachment) -> String {
    let table = nft_table_name(attachment);
    format!(
        r#"table netdev {table} {{
    chain ingress {{
        type filter hook ingress device "{tap}" priority -500; policy accept;
        ether saddr != {mac} counter drop
        ether type vlan counter drop
        ether type 8021ad counter drop
        ether type ip udp sport 67 counter drop
        ether type ip accept
        ether type arp accept
        ether type ip6 counter drop
        counter drop
    }}
}}
"#,
        tap = attachment.tap,
        mac = attachment.mac,
    )
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    if !output.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn run_with_stdin(program: &str, args: &[&str], input: &str) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute {program}"))?;
    child
        .stdin
        .take()
        .context("missing child stdin")?
        .write_all(input.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tap_and_table_names_are_deterministic_and_bounded() {
        let tap = tap_name("123e4567-e89b-12d3-a456-426614174000", 12).unwrap();
        assert!(tap.starts_with("dst"));
        assert!(tap.len() <= 15);
        assert_eq!(
            tap,
            tap_name("123e4567-e89b-12d3-a456-426614174000", 12).unwrap()
        );
    }

    #[test]
    fn nft_policy_checks_mac_before_protocol_exceptions() {
        let attachment = NicAttachment {
            vm_id: "vm-1".into(),
            nic_index: 0,
            bridge: "br0".into(),
            tap: tap_name("vm-1", 0).unwrap(),
            mac: "02:aa:bb:cc:dd:ee".into(),
        };
        let rules = nft_rules(&attachment);
        assert!(rules.find("ether saddr !=").unwrap() < rules.find("udp sport 67").unwrap());
        assert!(rules.contains("ether type ip6 counter drop"));
    }

    #[test]
    fn attachment_identity_cannot_select_a_tap_name() {
        let attachment = NicAttachment {
            vm_id: "vm-1".into(),
            nic_index: 0,
            bridge: "br0".into(),
            tap: "eth0".into(),
            mac: "02:aa:bb:cc:dd:ee".into(),
        };
        assert_ne!(
            attachment.tap,
            tap_name(&attachment.vm_id, attachment.nic_index).unwrap()
        );
    }

    #[test]
    fn rejects_multicast_and_malformed_mac_addresses() {
        assert!(validate_mac("02:aa:bb:cc:dd:ee").is_ok());
        assert!(validate_mac("01:aa:bb:cc:dd:ee").is_err());
        assert!(validate_mac("not-a-mac").is_err());
    }
}
