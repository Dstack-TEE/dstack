// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Small privileged broker for TAP creation and libvirt nwfilter bindings.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions, Permissions},
    io::Write as _,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::UnixStream as StdUnixStream,
        },
    },
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
use tracing::{info, warn};
use uuid::Uuid;
use wait_timeout::ChildExt;

use crate::config::NetdConfig;

const MAX_MESSAGE_SIZE: u64 = 64 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(35);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const IP_PATH: &str = "/usr/sbin/ip";
const VIRSH_PATH: &str = "/usr/bin/virsh";
const LOCK_PATH: &str = "/run/lock/dstack-netd.lock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceIdentity {
    pub instance_id: String,
    pub vm_id: String,
    pub nic_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareBridgeRequest {
    #[serde(flatten)]
    pub identity: InterfaceIdentity,
    pub bridge: String,
    pub mac: String,
    pub qemu_uid: u32,
    pub filter: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareMacvtapRequest {
    #[serde(flatten)]
    pub identity: InterfaceIdentity,
    pub parent: String,
    pub mac: String,
    #[serde(default)]
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    PrepareBridge(PrepareBridgeRequest),
    PrepareMacvtap(PrepareMacvtapRequest),
    Remove {
        #[serde(flatten)]
        identity: InterfaceIdentity,
    },
    /// Verify a deterministic TAP and binding for operations and integration
    /// diagnostics. The VMM startup path uses Prepare rather than Check.
    Check {
        #[serde(flatten)]
        identity: InterfaceIdentity,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn tap_name(identity: &InterfaceIdentity) -> String {
    let input = format!(
        "{}\0{}\0{}",
        identity.instance_id, identity.vm_id, identity.nic_index
    );
    let digest = Sha256::digest(input.as_bytes());
    format!("dt{}", hex::encode(&digest[..6]))
}

pub fn instance_id(configured: &str, run_path: &Path) -> String {
    if !configured.trim().is_empty() {
        return configured.trim().to_string();
    }
    let digest = Sha256::digest(run_path.as_os_str().as_encoded_bytes());
    format!("path-{}", hex::encode(&digest[..8]))
}

pub struct PreparedInterface {
    pub device: Option<String>,
}

pub async fn request(socket: &Path, request: &Request) -> Result<PreparedInterface> {
    let operation = match request {
        Request::PrepareBridge(_) => "prepare_bridge",
        Request::PrepareMacvtap(_) => "prepare_macvtap",
        Request::Remove { .. } => "remove",
        Request::Check { .. } => "check",
    };
    let exchange = async {
        let mut stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("failed to connect to netd at {}", socket.display()))?;
        let message = serde_json::to_vec(request)?;
        if message.len() as u64 > MAX_MESSAGE_SIZE {
            bail!("netd request is too large");
        }
        stream.write_all(&message).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream
            .take(MAX_MESSAGE_SIZE + 1)
            .read_to_end(&mut response)
            .await?;
        if response.len() as u64 > MAX_MESSAGE_SIZE {
            bail!("netd response is too large");
        }
        let response: Response =
            serde_json::from_slice(&response).context("failed to decode netd response")?;
        if !response.ok {
            bail!(
                "netd {operation} failed: {}",
                response.error.as_deref().unwrap_or("unknown error")
            );
        }
        Ok(PreparedInterface {
            device: {
                response.tap.context("netd response omitted TAP name")?;
                response.device
            },
        })
    };
    timeout(Duration::from_secs(30), exchange)
        .await
        .context("timed out waiting for netd")?
}

pub async fn serve(config: NetdConfig) -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("netd must run as root");
    }
    require_executable(IP_PATH)?;
    require_executable(VIRSH_PATH)?;
    let listener = {
        let _lock = OperationLock::acquire()?;
        prepare_socket_path(&config.socket)?;
        UnixListener::bind(&config.socket)
            .with_context(|| format!("failed to bind netd socket {}", config.socket.display()))?
    };
    // Access control is based on SO_PEERCRED rather than filesystem groups so
    // one shared service can authorize VMM instances running under different
    // UIDs and development mode needs no system group setup.
    std::fs::set_permissions(&config.socket, Permissions::from_mode(0o666))?;
    info!(socket = %config.socket.display(), "netd listening");
    loop {
        let (mut stream, _) = listener.accept().await?;
        // This timeout bounds async socket reads and writes. handle_request is
        // synchronous, so helper execution is bounded separately by
        // COMMAND_TIMEOUT rather than preempted by this future timeout.
        match timeout(CONNECTION_TIMEOUT, serve_connection(&config, &mut stream)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "netd connection failed"),
            Err(_) => warn!("netd connection timed out"),
        }
    }
}

async fn serve_connection(config: &NetdConfig, stream: &mut UnixStream) -> Result<()> {
    let uid = peer_uid(stream)?;
    let allowed = uid == 0 || config.allowed_uids.contains(&uid);
    let response = if allowed {
        match read_request(stream)
            .await
            .and_then(|request| handle_request(&config.libvirt_uri, request))
        {
            Ok((tap, device)) => Response {
                ok: true,
                tap: Some(tap),
                device,
                error: None,
            },
            Err(error) => {
                warn!(%uid, %error, "netd request failed");
                Response {
                    ok: false,
                    tap: None,
                    device: None,
                    error: Some(format!("{error:#}")),
                }
            }
        }
    } else {
        warn!(%uid, "rejected unauthorized netd client");
        Response {
            ok: false,
            tap: None,
            device: None,
            error: Some("caller UID is not authorized".into()),
        }
    };
    let encoded = serde_json::to_vec(&response)?;
    stream.write_all(&encoded).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let mut message = Vec::new();
    stream
        .take(MAX_MESSAGE_SIZE + 1)
        .read_to_end(&mut message)
        .await?;
    if message.len() as u64 > MAX_MESSAGE_SIZE {
        bail!("request exceeds {MAX_MESSAGE_SIZE} bytes");
    }
    serde_json::from_slice(&message).context("invalid netd request")
}

fn handle_request(libvirt_uri: &str, request: Request) -> Result<(String, Option<String>)> {
    let _lock = OperationLock::acquire()?;
    match request {
        Request::PrepareBridge(request) => {
            prepare_bridge(libvirt_uri, &request).map(|tap| (tap, None))
        }
        Request::PrepareMacvtap(request) => prepare_macvtap(
            libvirt_uri,
            &request.identity,
            &request.parent,
            &request.mac,
            &request.mode,
        )
        .map(|(tap, device)| (tap, Some(device))),
        Request::Remove { identity } => {
            validate_identity(&identity)?;
            let tap = tap_name(&identity);
            remove_interface(libvirt_uri, &tap)?;
            Ok((tap, None))
        }
        Request::Check { identity } => {
            validate_identity(&identity)?;
            let tap = tap_name(&identity);
            if !Path::new("/sys/class/net").join(&tap).exists() {
                bail!("TAP {tap} does not exist");
            }
            if !is_macvtap(&tap) {
                virsh(libvirt_uri, &["nwfilter-binding-dumpxml", &tap], None)?;
            }
            Ok((tap, None))
        }
    }
}

fn prepare_macvtap(
    libvirt_uri: &str,
    identity: &InterfaceIdentity,
    parent: &str,
    mac: &str,
    mode: &str,
) -> Result<(String, String)> {
    validate_identity(identity)?;
    validate_name("parent", parent, 15, "_.-")?;
    if !Path::new("/sys/class/net").join(parent).exists() {
        bail!("parent interface {parent} does not exist");
    }
    validate_mac(mac)?;
    let mode = if mode.is_empty() { "private" } else { mode };
    if !matches!(mode, "private" | "bridge" | "vepa" | "passthru") {
        bail!("invalid macvtap mode");
    }
    let tap = tap_name(identity);
    remove_interface(libvirt_uri, &tap)?;
    ip(&[
        "link", "add", "link", parent, "name", &tap, "address", mac, "type", "macvtap", "mode",
        mode,
    ])?;
    let result = (|| {
        let ifindex =
            std::fs::read_to_string(Path::new("/sys/class/net").join(&tap).join("ifindex"))
                .context("failed to read macvtap ifindex")?;
        let device = format!("/dev/tap{}", ifindex.trim());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !Path::new(&device).exists() {
            if std::time::Instant::now() >= deadline {
                bail!("timed out waiting for macvtap device {device}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let metadata = std::fs::symlink_metadata(&device)
            .with_context(|| format!("failed to inspect macvtap device {device}"))?;
        if !metadata.file_type().is_char_device() {
            bail!("macvtap device {device} is not a character device");
        }
        ip(&["link", "set", "dev", &tap, "up"])?;
        Ok(device)
    })();
    match result {
        Ok(device) => {
            info!(%tap, %parent, %mode, %device, "prepared macvtap");
            Ok((tap, device))
        }
        Err(error) => {
            let _ = remove_interface(libvirt_uri, &tap);
            Err(error)
        }
    }
}

struct OperationLock(File);

impl OperationLock {
    fn acquire() -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(LOCK_PATH)
            .with_context(|| format!("failed to open {LOCK_PATH}"))?;
        // SAFETY: flock only acts on the valid file descriptor owned by file.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("failed to lock netd operations");
        }
        Ok(Self(file))
    }
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        // SAFETY: the file remains alive until after Drop returns.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn prepare_bridge(libvirt_uri: &str, request: &PrepareBridgeRequest) -> Result<String> {
    validate_prepare_bridge(request)?;
    let tap = tap_name(&request.identity);
    // A failed VMM start may leave a deterministic resource behind. Replacing
    // it makes prepare idempotent without accepting a caller-selected TAP.
    remove_interface(libvirt_uri, &tap)?;

    let uid = request.qemu_uid.to_string();
    ip(&["tuntap", "add", "dev", &tap, "mode", "tap", "user", &uid])?;
    let result = (|| {
        ip(&["link", "set", "dev", &tap, "master", &request.bridge])?;
        let xml = binding_xml(request, &tap);
        virsh(
            libvirt_uri,
            &["nwfilter-binding-create", "--validate", "/dev/stdin"],
            Some(xml.as_bytes()),
        )?;
        ip(&["link", "set", "dev", &tap, "up"])?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = remove_interface(libvirt_uri, &tap);
        return Err(error);
    }
    info!(%tap, bridge = %request.bridge, filter = %request.filter, "prepared filtered TAP");
    Ok(tap)
}

fn remove_interface(libvirt_uri: &str, tap: &str) -> Result<()> {
    let macvtap = is_macvtap(tap);
    if Path::new("/sys/class/net").join(tap).exists() {
        let _ = ip(&["link", "set", "dev", tap, "down"]);
    }
    if !macvtap {
        delete_binding(libvirt_uri, tap)?;
    }
    if Path::new("/sys/class/net").join(tap).exists() {
        ip(&["link", "delete", "dev", tap])?;
        info!(%tap, "removed filtered TAP");
    }
    Ok(())
}

fn is_macvtap(interface: &str) -> bool {
    Path::new("/sys/class/net")
        .join(interface)
        .join("macvtap")
        .exists()
}

fn delete_binding(uri: &str, tap: &str) -> Result<()> {
    let output = Command::new(VIRSH_PATH)
        .args(["--connect", uri, "nwfilter-binding-delete", tap])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to execute virsh")?;
    if output.status.success() {
        return Ok(());
    }
    let error = String::from_utf8_lossy(&output.stderr);
    if error.contains("Network filter binding not found") {
        return Ok(());
    }
    bail!("virsh failed to delete binding {tap}: {}", error.trim())
}

fn binding_xml(request: &PrepareBridgeRequest, tap: &str) -> String {
    let owner_uuid = stable_uuid(&request.identity);
    let owner_name = format!(
        "dstack:{}:{}:{}",
        request.identity.instance_id, request.identity.vm_id, request.identity.nic_index
    );
    let mut parameters = String::new();
    for (name, value) in &request.parameters {
        parameters.push_str(&format!(
            "<parameter name='{}' value='{}'/>",
            xml_escape(name),
            xml_escape(value)
        ));
    }
    format!(
        "<filterbinding><owner><name>{}</name><uuid>{}</uuid></owner>\
         <portdev name='{}'/><mac address='{}'/>\
         <filterref filter='{}'>{}</filterref></filterbinding>",
        xml_escape(&owner_name),
        owner_uuid,
        xml_escape(tap),
        xml_escape(&request.mac),
        xml_escape(&request.filter),
        parameters
    )
}

fn stable_uuid(identity: &InterfaceIdentity) -> Uuid {
    let digest = Sha256::digest(
        format!(
            "{}\0{}\0{}",
            identity.instance_id, identity.vm_id, identity.nic_index
        )
        .as_bytes(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn validate_prepare_bridge(request: &PrepareBridgeRequest) -> Result<()> {
    validate_identity(&request.identity)?;
    validate_name("bridge", &request.bridge, 15, "_.-")?;
    if !Path::new("/sys/class/net")
        .join(&request.bridge)
        .join("bridge")
        .exists()
    {
        bail!("{} is not a host bridge", request.bridge);
    }
    validate_mac(&request.mac)?;
    validate_name("filter", &request.filter, 128, "_.:-")?;
    if request.parameters.len() > 64 {
        bail!("too many nwfilter parameters");
    }
    for (name, value) in &request.parameters {
        validate_name("parameter name", name, 64, "_")?;
        if value.len() > 512 || value.contains('\0') {
            bail!("invalid nwfilter parameter value");
        }
    }
    Ok(())
}

fn validate_identity(identity: &InterfaceIdentity) -> Result<()> {
    for (label, value) in [
        ("instance ID", identity.instance_id.as_str()),
        ("VM ID", identity.vm_id.as_str()),
    ] {
        if value.is_empty() || value.len() > 128 || value.contains('\0') {
            bail!("invalid {label}");
        }
    }
    if identity.nic_index > 255 {
        bail!("NIC index is out of range");
    }
    Ok(())
}

fn validate_name(label: &str, value: &str, max: usize, punctuation: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || punctuation.contains(ch))
    {
        bail!("invalid {label}");
    }
    Ok(())
}

fn validate_mac(mac: &str) -> Result<()> {
    let bytes = mac
        .split(':')
        .map(|part| {
            if part.len() != 2 {
                bail!("invalid MAC address");
            }
            u8::from_str_radix(part, 16).context("invalid MAC address")
        })
        .collect::<Result<Vec<_>>>()?;
    if bytes.len() != 6 || bytes[0] & 1 != 0 {
        bail!("invalid unicast MAC address");
    }
    Ok(())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

fn ip(args: &[&str]) -> Result<()> {
    run_command(IP_PATH, args, None)
}

fn virsh(uri: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<()> {
    let mut full_args = vec!["--connect", uri];
    full_args.extend_from_slice(args);
    run_command(VIRSH_PATH, &full_args, stdin)
}

fn run_command(program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<()> {
    run_command_with_timeout(program, args, stdin, COMMAND_TIMEOUT)
}

fn run_command_with_timeout(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    command_timeout: Duration,
) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute {program}"))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .context("missing command stdin")?
            .write_all(input)?;
    }
    if child.wait_timeout(command_timeout)?.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        bail!(
            "{} timed out after {command_timeout:?}",
            Path::new(program).display()
        );
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        bail!("{} failed: {}", Path::new(program).display(), error.trim());
    }
    Ok(())
}

fn require_executable(path: &str) -> Result<()> {
    if !Path::new(path).is_file() {
        bail!("required executable {path} does not exist");
    }
    Ok(())
}

fn prepare_socket_path(socket: &Path) -> Result<()> {
    let parent = socket.parent().context("netd socket has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    if socket.exists() {
        if StdUnixStream::connect(socket).is_ok() {
            bail!("another netd is listening at {}", socket.display());
        }
        std::fs::remove_file(socket)
            .with_context(|| format!("failed to remove stale socket {}", socket.display()))?;
    }
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials and length point to valid writable storage of the
    // exact size passed to getsockopt, and the stream owns a valid socket FD.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to read peer credentials");
    }
    Ok(credentials.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(instance: &str, vm: &str, nic_index: usize) -> InterfaceIdentity {
        InterfaceIdentity {
            instance_id: instance.into(),
            vm_id: vm.into(),
            nic_index,
        }
    }

    #[test]
    fn tap_names_are_stable_bounded_and_namespaced() {
        let first = tap_name(&identity("one", "vm", 0));
        assert_eq!(first, tap_name(&identity("one", "vm", 0)));
        assert_ne!(first, tap_name(&identity("two", "vm", 0)));
        assert_ne!(first, tap_name(&identity("one", "vm", 1)));
        assert!(first.len() <= 15);
    }

    #[test]
    fn binding_xml_escapes_values() {
        let request = PrepareBridgeRequest {
            identity: identity("instance<&", "vm", 0),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filter: "clean-traffic".into(),
            parameters: BTreeMap::from([("IP".into(), "10.0.0.2<&".into())]),
        };
        let xml = binding_xml(&request, "dt123");
        assert!(xml.contains("instance&lt;&amp;"));
        assert!(xml.contains("10.0.0.2&lt;&amp;"));
        assert!(!xml.contains("instance<&"));
    }

    #[test]
    fn validation_rejects_injected_host_names() {
        assert!(validate_name("bridge", "br0;id", 15, "_.-").is_err());
        assert!(validate_name("filter", "../../filter", 128, "_.:-").is_err());
        assert!(validate_mac("ff:ff:ff:ff:ff:ff").is_err());
    }

    #[test]
    fn remove_protocol_keeps_identity_fields_flat() {
        let request = Request::Remove {
            identity: identity("instance", "vm", 2),
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["operation"], "remove");
        assert_eq!(value["instance_id"], "instance");
        assert_eq!(value["vm_id"], "vm");
        assert_eq!(value["nic_index"], 2);
        assert!(value.get("identity").is_none());
    }

    #[test]
    fn macvtap_prepare_has_a_dedicated_operation() {
        let request = Request::PrepareMacvtap(PrepareMacvtapRequest {
            identity: identity("instance", "vm", 1),
            parent: "eth0".into(),
            mac: "02:00:00:00:00:01".into(),
            mode: "private".into(),
        });
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["operation"], "prepare_macvtap");
        assert_eq!(value["instance_id"], "instance");
        assert_eq!(value["parent"], "eth0");
        assert!(value.get("identity").is_none());
    }

    #[test]
    fn bridge_prepare_has_a_dedicated_operation() {
        let request = Request::PrepareBridge(PrepareBridgeRequest {
            identity: identity("instance", "vm", 0),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filter: "clean-traffic".into(),
            parameters: BTreeMap::new(),
        });
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["operation"], "prepare_bridge");
        assert_eq!(value["instance_id"], "instance");
        assert_eq!(value["bridge"], "br0");
        assert!(value.get("identity").is_none());
    }

    #[tokio::test]
    async fn disconnected_client_is_confined_to_one_connection() {
        let (mut server, client) = UnixStream::pair().unwrap();
        drop(client);
        let result = timeout(
            Duration::from_secs(1),
            serve_connection(&NetdConfig::default(), &mut server),
        )
        .await;
        assert!(result.is_ok(), "disconnected peer blocked the handler");
        // Either the EOF is reported while reading or the response write sees
        // EPIPE. In both cases serve() logs this per-connection error and keeps
        // accepting clients.
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn command_timeout_kills_stalled_tool() {
        let started = std::time::Instant::now();
        let error = run_command_with_timeout(
            "/bin/sh",
            &["-c", "sleep 10"],
            None,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
