// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Small privileged broker for TAP creation and libvirt nwfilter bindings.

use std::{
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
use listenfd::ListenFd;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
use tracing::{debug, info, warn};
use uuid::Uuid;
use wait_timeout::ChildExt;

use crate::config::{NetdConfig, NetworkFilterConfig};

const MAX_MESSAGE_SIZE: u64 = 64 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(35);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const IP_PATH: &str = "/usr/sbin/ip";
const VIRSH_PATH: &str = "/usr/bin/virsh";
const LOCK_PATH: &str = "/run/lock/dstack-netd.lock";
/// Upper bound on TAP queue pairs netd will create. Mirrors the VMM's own cap
/// so a malformed request cannot ask the kernel for an unbounded device.
const MAX_QUEUES: u32 = 64;

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
    /// Whether to bind an nwfilter to the TAP. *Which* filter, and with what
    /// parameters, is netd's own configuration to decide -- a caller that named
    /// them could name one that filters nothing, or pin the binding to the
    /// gateway's MAC and IP, and still satisfy a node policy that only asked
    /// for "some filter". An unfiltered TAP is what multiqueue bridge
    /// networking needs on nodes that do not run libvirt.
    pub filtered: bool,
    /// virtio-net queue pairs. Zero or one creates a single-queue TAP. QEMU
    /// rejects a device whose `IFF_MULTI_QUEUE` state differs from its own
    /// `queues=` argument, so this must match the launch exactly.
    pub queues: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareMacvtapRequest {
    #[serde(flatten)]
    pub identity: InterfaceIdentity,
    pub parent: String,
    pub mac: String,
    pub qemu_uid: u32,
    #[serde(default)]
    pub mode: String,
    /// virtio-net queue pairs. The device is created with matching hardware
    /// queues; QEMU then opens the character device once per queue.
    #[serde(default)]
    pub queues: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    PrepareBridge(PrepareBridgeRequest),
    PrepareMacvtap(PrepareMacvtapRequest),
    Remove {
        #[serde(flatten)]
        identity: InterfaceIdentity,
        /// Whether this interface was created with an nwfilter binding.
        /// Macvtap TAPs never carry one, and removal detects them rather than
        /// trusting this field.
        filtered: bool,
    },
    /// Verify a deterministic TAP and binding for operations and integration
    /// diagnostics. The VMM startup path uses Prepare rather than Check.
    Check {
        #[serde(flatten)]
        identity: InterfaceIdentity,
        filtered: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    /// Queue pairs the interface was actually created with. Absent from a netd
    /// that predates multiqueue, which is how the VMM tells the difference
    /// between "one queue was requested" and "this netd ignored the request".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queues: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// What netd built, echoed back so the caller can verify it matches the
/// request before handing the interface to QEMU.
struct Prepared {
    tap: String,
    device: Option<String>,
    queues: Option<u32>,
}

impl Prepared {
    fn tap(tap: String) -> Self {
        Self {
            tap,
            device: None,
            queues: None,
        }
    }
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
    pub queues: Option<u32>,
}

/// Marker carried in the error chain when the VMM could not reach netd at all.
///
/// "netd refused this" and "netd is not there" call for different advice, and
/// the caller cannot tell them apart from the message alone -- a callback probe
/// afterwards would answer about a different moment.
#[derive(Debug)]
pub struct Unreachable;

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("netd is not reachable")
    }
}

impl std::error::Error for Unreachable {}

/// Whether this error means netd was never reached.
pub fn is_unreachable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<Unreachable>())
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
            .map_err(anyhow::Error::from)
            .context(Unreachable)
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
        response.tap.context("netd response omitted TAP name")?;
        Ok(PreparedInterface {
            device: response.device,
            queues: response.queues,
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
    config.validate()?;
    require_executable(IP_PATH)?;
    require_executable(VIRSH_PATH)?;
    let listener = match activated_listener()? {
        Some(listener) => listener,
        None => bind_listener(&config)?,
    };
    info!(address = ?listener.local_addr()?, "netd listening");
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

fn activated_listener() -> Result<Option<UnixListener>> {
    let mut listenfd = ListenFd::from_env();
    if listenfd.len() == 0 {
        return Ok(None);
    }
    if listenfd.len() != 1 {
        bail!(
            "netd requires exactly one systemd-activated socket, received {}",
            listenfd.len()
        );
    }
    let listener = listenfd
        .take_unix_listener(0)
        .context("systemd fd 0 is not a Unix stream listener")?
        .context("systemd did not provide fd 0")?;
    listener.set_nonblocking(true)?;
    info!("using systemd-activated socket");
    Ok(Some(UnixListener::from_std(listener)?))
}

fn bind_listener(config: &NetdConfig) -> Result<UnixListener> {
    let listener = {
        let _lock = OperationLock::acquire()?;
        prepare_socket_path(&config.socket)?;
        UnixListener::bind(&config.socket)
            .with_context(|| format!("failed to bind netd socket {}", config.socket.display()))?
    };
    std::fs::set_permissions(&config.socket, Permissions::from_mode(config.socket_mode))?;
    Ok(listener)
}

async fn serve_connection(config: &NetdConfig, stream: &mut UnixStream) -> Result<()> {
    // Access is authorized by the Unix socket's owner, group, and mode. Any
    // process that can connect is trusted with the complete netd protocol.
    let outcome = match read_request(stream).await {
        // A peer that connects and closes without sending is the VMM's
        // reachability check: netd that died leaves its socket behind, so the
        // VMM connects to tell the two apart. Answering that with a parse error
        // and a warning would fill the log with reports of it working.
        Ok(None) => {
            debug!("netd liveness probe");
            return Ok(());
        }
        Ok(Some(request)) => handle_request(config, request),
        // A request that arrived but could not be understood still gets an
        // answer. A VMM newer than this netd sends operations it does not
        // know, and "unknown variant `prepare_foo`" is what tells the operator
        // to upgrade; a closed connection tells them nothing.
        Err(error) => Err(error),
    };
    let response = match outcome {
        Ok(prepared) => Response {
            ok: true,
            tap: Some(prepared.tap),
            device: prepared.device,
            queues: prepared.queues,
            error: None,
        },
        Err(error) => {
            warn!(%error, "netd request failed");
            Response {
                ok: false,
                tap: None,
                device: None,
                queues: None,
                error: Some(format!("{error:#}")),
            }
        }
    };
    let encoded = serde_json::to_vec(&response)?;
    stream.write_all(&encoded).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Reads one request, or `None` if the peer closed without sending anything.
async fn read_request(stream: &mut UnixStream) -> Result<Option<Request>> {
    let mut message = Vec::new();
    stream
        .take(MAX_MESSAGE_SIZE + 1)
        .read_to_end(&mut message)
        .await?;
    if message.is_empty() {
        return Ok(None);
    }
    if message.len() as u64 > MAX_MESSAGE_SIZE {
        bail!("request exceeds {MAX_MESSAGE_SIZE} bytes");
    }
    serde_json::from_slice(&message)
        .map(Some)
        .context("invalid netd request")
}

fn handle_request(config: &NetdConfig, request: Request) -> Result<Prepared> {
    let libvirt_uri = config.libvirt_uri.as_str();
    let _lock = OperationLock::acquire()?;
    match request {
        Request::PrepareBridge(request) => {
            prepare_bridge(libvirt_uri, &request, config.filter_policy())
        }
        Request::PrepareMacvtap(request) => {
            prepare_macvtap(libvirt_uri, &request, config.filter_policy())
        }
        Request::Remove { identity, filtered } => {
            validate_identity(&identity)?;
            let tap = tap_name(&identity);
            remove_interface(libvirt_uri, &tap, binding_cleanup(filtered))?;
            Ok(Prepared::tap(tap))
        }
        Request::Check { identity, filtered } => {
            validate_identity(&identity)?;
            let tap = tap_name(&identity);
            if !Path::new("/sys/class/net").join(&tap).exists() {
                bail!("TAP {tap} does not exist");
            }
            // An unfiltered TAP has no binding to dump; asking for one would
            // report a healthy multiqueue interface as broken.
            if filtered && !is_macvtap(&tap) {
                virsh(libvirt_uri, &["nwfilter-binding-dumpxml", &tap], None)?;
            }
            Ok(Prepared::tap(tap))
        }
    }
}

fn prepare_macvtap(
    libvirt_uri: &str,
    request: &PrepareMacvtapRequest,
    filter: &NetworkFilterConfig,
) -> Result<Prepared> {
    let identity = &request.identity;
    let parent = request.parent.as_str();
    let qemu_uid = request.qemu_uid;
    validate_identity(identity)?;
    validate_name("parent", parent, 15, "_.-")?;
    if !Path::new("/sys/class/net").join(parent).exists() {
        bail!("parent interface {parent} does not exist");
    }
    // A macvtap parent may be a bridge, and libvirt nwfilter does not apply to
    // macvtap. So on a node that requires every bridge TAP to be filtered, a
    // macvtap request naming that same bridge is the identical unfiltered L2
    // access the policy exists to refuse, spelled with a different operation.
    // An interface enslaved to a bridge reaches the same segment.
    if filter.requires_binding() {
        let sysfs = Path::new("/sys/class/net").join(parent);
        if sysfs.join("bridge").exists() {
            bail!("this netd requires filtering, so {parent} may not be a macvtap parent: it is a host bridge");
        }
        if sysfs.join("master").exists() {
            bail!("this netd requires filtering, so {parent} may not be a macvtap parent: it is enslaved to a bridge");
        }
    }
    validate_mac(&request.mac)?;
    let mac = request.mac.as_str();
    let mode = if request.mode.is_empty() {
        "private"
    } else {
        request.mode.as_str()
    };
    if !matches!(mode, "private" | "bridge" | "vepa" | "passthru") {
        bail!("invalid macvtap mode");
    }
    let queues = validate_queues(request.queues)?;
    let tap = tap_name(identity);
    remove_interface(libvirt_uri, &tap, BindingCleanup::BestEffort)?;
    let queue_count = queues.to_string();
    let mut add = vec!["link", "add", "link", parent, "name", &tap, "address", mac];
    if queues > 1 {
        // macvtap defaults to a single hardware queue pair. Without this the
        // extra tap queues exist but the lower device still serializes.
        add.extend_from_slice(&["numtxqueues", &queue_count, "numrxqueues", &queue_count]);
    }
    add.extend_from_slice(&["type", "macvtap", "mode", mode]);
    ip(&add)?;
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
        std::os::unix::fs::chown(&device, Some(qemu_uid), None)
            .with_context(|| format!("failed to set owner of macvtap device {device}"))?;
        ip(&["link", "set", "dev", &tap, "up"])?;
        Ok(device)
    })();
    match result {
        Ok(device) => {
            info!(%tap, %parent, %mode, %device, %queues, "prepared macvtap");
            Ok(Prepared {
                tap,
                device: Some(device),
                queues: Some(queues),
            })
        }
        Err(error) => {
            let _ = remove_interface(libvirt_uri, &tap, BindingCleanup::BestEffort);
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

fn prepare_bridge(
    libvirt_uri: &str,
    request: &PrepareBridgeRequest,
    filter: &NetworkFilterConfig,
) -> Result<Prepared> {
    validate_prepare_bridge(request, filter)?;
    let filtered = request.filtered;
    let tap = tap_name(&request.identity);
    // A failed VMM start may leave a deterministic resource behind. Replacing
    // it makes prepare idempotent without accepting a caller-selected TAP.
    remove_interface(libvirt_uri, &tap, binding_cleanup(filtered))?;

    let uid = request.qemu_uid.to_string();
    let queues = validate_queues(request.queues)?;
    let mut add = vec!["tuntap", "add", "dev", &tap, "mode", "tap"];
    if queues > 1 {
        // QEMU refuses to attach when the device's IFF_MULTI_QUEUE state does
        // not match its own `queues=` argument, in either direction.
        add.push("multi_queue");
    }
    add.extend_from_slice(&["user", &uid]);
    ip(&add)?;
    let result = (|| {
        ip(&["link", "set", "dev", &tap, "master", &request.bridge])?;
        if filtered {
            let xml = binding_xml(request, &tap, filter);
            virsh(
                libvirt_uri,
                &["nwfilter-binding-create", "--validate", "/dev/stdin"],
                Some(xml.as_bytes()),
            )?;
        }
        ip(&["link", "set", "dev", &tap, "up"])?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = remove_interface(libvirt_uri, &tap, BindingCleanup::BestEffort);
        return Err(error);
    }
    info!(%tap, bridge = %request.bridge, %filtered, %queues, "prepared TAP");
    Ok(Prepared {
        tap,
        device: None,
        queues: Some(queues),
    })
}

/// How hard removal must try to clear an nwfilter binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingCleanup {
    /// The binding must be gone before this returns, because the caller is
    /// about to create one at the same interface name and libvirt refuses a
    /// duplicate.
    Required,
    /// Delete a binding if libvirt can be reached, but do not fail the removal
    /// when it cannot. Unfiltered TAPs live on nodes where `libvirtd` need not
    /// be running at all, and a stale binding left by an earlier, filtered
    /// interface at this name is still worth clearing when it is.
    BestEffort,
}

fn remove_interface(libvirt_uri: &str, tap: &str, cleanup: BindingCleanup) -> Result<()> {
    let macvtap = is_macvtap(tap);
    if Path::new("/sys/class/net").join(tap).exists() {
        let _ = ip(&["link", "set", "dev", tap, "down"]);
    }
    // A macvtap interface never carries a binding. Anything else might: this
    // name may have been a filtered bridge TAP before, and the binding
    // outlives the interface.
    if !macvtap {
        match cleanup {
            BindingCleanup::Required => delete_binding(libvirt_uri, tap)?,
            BindingCleanup::BestEffort => {
                // netd refuses to start without virsh, so the binary is always
                // here; libvirtd need not be running, and on a node that only
                // wants macvtap or multiqueue it usually is not.
                if let Err(error) = delete_binding(libvirt_uri, tap) {
                    warn!(%tap, "could not clear a possible nwfilter binding: {error:#}");
                }
            }
        }
    }
    if Path::new("/sys/class/net").join(tap).exists() {
        ip(&["link", "delete", "dev", tap])?;
        info!(%tap, "removed managed network interface");
    }
    Ok(())
}

fn is_macvtap(interface: &str) -> bool {
    Path::new("/sys/class/net")
        .join(interface)
        .join("macvtap")
        .exists()
}

/// Deletes an interface's nwfilter binding, if it has one.
///
/// Goes through the same `COMMAND_TIMEOUT`-bounded helper as every other virsh
/// call. netd's accept loop is strictly serialized, so an unbounded call here
/// would let one unreachable libvirt stall every other VM's prepare and remove.
fn delete_binding(uri: &str, tap: &str) -> Result<()> {
    match virsh(uri, &["nwfilter-binding-delete", tap], None) {
        Ok(()) => Ok(()),
        // Removal is idempotent. Having no binding is the normal case for
        // macvtap, for unfiltered multiqueue TAPs, and for any name being
        // reused after an earlier removal already cleared it.
        Err(error)
            if error
                .to_string()
                .contains("Network filter binding not found") =>
        {
            Ok(())
        }
        Err(error) => Err(error).context(format!("virsh failed to delete binding {tap}")),
    }
}

fn binding_xml(request: &PrepareBridgeRequest, tap: &str, filter: &NetworkFilterConfig) -> String {
    let owner_uuid = stable_uuid(&request.identity);
    let owner_name = format!(
        "dstack:{}:{}:{}",
        request.identity.instance_id, request.identity.vm_id, request.identity.nic_index
    );
    let mut parameters = String::new();
    for (name, value) in &filter.parameters {
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
        xml_escape(&filter.filter),
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

fn validate_prepare_bridge(
    request: &PrepareBridgeRequest,
    filter: &NetworkFilterConfig,
) -> Result<()> {
    validate_identity(&request.identity)?;
    validate_name("bridge", &request.bridge, 15, "_.-")?;
    // Unfiltered bridge TAPs exist for unfiltered multiqueue, and netd holds
    // that policy itself rather than trusting the caller with it. netd is the
    // privileged side of this socket; on a node configured to filter bridge
    // traffic, "build me a TAP on br0 with no nwfilter binding" is precisely
    // the request the boundary exists to refuse, and anything that can reach
    // the socket can make it.
    //
    // Refused before the host is inspected: this is about the request, not
    // about what happens to exist on this machine.
    if filter.requires_binding() && !request.filtered {
        bail!("this netd requires an nwfilter binding on every bridge TAP");
    }
    if !Path::new("/sys/class/net")
        .join(&request.bridge)
        .join("bridge")
        .exists()
    {
        bail!("{} is not a host bridge", request.bridge);
    }
    validate_mac(&request.mac)?;
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

/// A caller that knows a binding is there needs it gone; one that does not
/// still clears whatever it finds, without failing when libvirt is absent.
fn binding_cleanup(filtered: bool) -> BindingCleanup {
    if filtered {
        BindingCleanup::Required
    } else {
        BindingCleanup::BestEffort
    }
}

/// Normalizes a requested queue pair count. Zero means the caller did not ask
/// for multiqueue, which is the same device shape as one queue pair.
fn validate_queues(queues: u32) -> Result<u32> {
    if queues > MAX_QUEUES {
        bail!("queues must not exceed {MAX_QUEUES}");
    }
    Ok(queues.max(1))
}

fn validate_name(label: &str, value: &str, max: usize, punctuation: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        // `.` and `..` pass the charset check below, and every name validated
        // here is then joined onto a sysfs path to ask whether the interface
        // exists. `/sys/class/net/..` exists, so the question would be answered
        // about a directory rather than about an interface.
        || value == "."
        || value == ".."
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

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
            filtered: true,
            queues: 0,
        };
        let filter = NetworkFilterConfig {
            mode: crate::config::NetworkFilterMode::Libvirt,
            filter: "clean-traffic".into(),
            parameters: BTreeMap::from([("IP".into(), "10.0.0.2<&".into())]),
        };
        let xml = binding_xml(&request, "dt123", &filter);
        assert!(xml.contains("instance&lt;&amp;"));
        assert!(xml.contains("10.0.0.2&lt;&amp;"));
        assert!(!xml.contains("instance<&"));
    }

    #[test]
    fn validation_rejects_injected_host_names() {
        assert!(validate_name("bridge", "br0;id", 15, "_.-").is_err());
        // `/sys/class/net/..` exists, so an existence check on this name would
        // answer about a directory rather than about an interface.
        assert!(validate_name("parent", "..", 15, "_.-").is_err());
        assert!(validate_name("parent", ".", 15, "_.-").is_err());
        assert!(validate_name("filter", "../../filter", 128, "_.:-").is_err());
        assert!(validate_mac("ff:ff:ff:ff:ff:ff").is_err());
    }

    #[test]
    fn remove_protocol_keeps_identity_fields_flat() {
        let request = Request::Remove {
            identity: identity("instance", "vm", 2),
            filtered: true,
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["operation"], "remove");
        assert_eq!(value["instance_id"], "instance");
        assert_eq!(value["vm_id"], "vm");
        assert_eq!(value["nic_index"], 2);
        assert!(value.get("identity").is_none());
    }

    #[test]
    fn bridge_prepare_protocol_is_named_explicitly() {
        let request = Request::PrepareBridge(PrepareBridgeRequest {
            identity: identity("instance", "vm", 0),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: true,
            queues: 0,
        });
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["operation"], "prepare_bridge");
        assert_eq!(value["instance_id"], "instance");
        assert_eq!(value["bridge"], "br0");
        assert!(value.get("identity").is_none());
    }

    /// `filtered` says which of two shapes was built, and both are reachable
    /// on any node this build can produce. There is no released peer that omits
    /// it -- netd does not exist before v0.6 -- so it is required rather than
    /// defaulted, and a request that leaves it out is a bug, not an old client.
    #[test]
    fn removal_states_which_shape_it_is_undoing() {
        let error = serde_json::from_value::<Request>(serde_json::json!({
            "operation": "remove",
            "instance_id": "instance",
            "vm_id": "vm",
            "nic_index": 0,
        }))
        .unwrap_err();
        assert!(error.to_string().contains("filtered"), "{error}");

        for filtered in [true, false] {
            let decoded: Request = serde_json::from_value(serde_json::json!({
                "operation": "remove",
                "instance_id": "instance",
                "vm_id": "vm",
                "nic_index": 0,
                "filtered": filtered,
            }))
            .unwrap();
            let Request::Remove {
                filtered: decoded, ..
            } = decoded
            else {
                panic!("wrong variant");
            };
            assert_eq!(decoded, filtered);
        }
    }

    /// A binding outlives the interface it was bound to, and TAP names are a
    /// deterministic hash of the VM identity, so the same name comes back.
    /// Removing an interface therefore clears whatever binding is there, and
    /// only insists when the caller is about to create a replacement.
    #[test]
    fn binding_cleanup_insists_only_when_a_replacement_follows() {
        assert_eq!(binding_cleanup(true), BindingCleanup::Required);
        assert_eq!(binding_cleanup(false), BindingCleanup::BestEffort);
    }

    #[test]
    fn queue_counts_normalize_to_at_least_one_and_stay_bounded() {
        assert_eq!(validate_queues(0).unwrap(), 1);
        assert_eq!(validate_queues(1).unwrap(), 1);
        assert_eq!(validate_queues(MAX_QUEUES).unwrap(), MAX_QUEUES);
        assert!(validate_queues(MAX_QUEUES + 1).is_err());
    }

    #[test]
    fn queue_count_travels_with_the_prepare_request() {
        let request = Request::PrepareBridge(PrepareBridgeRequest {
            identity: identity("instance", "vm", 0),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: false,
            queues: 4,
        });
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["queues"], 4);
        assert_eq!(value["filtered"], false);

        // QEMU refuses a device whose IFF_MULTI_QUEUE state disagrees with its
        // own `queues=`, so a request that leaves the count to netd's
        // imagination is one netd must not answer.
        let error = serde_json::from_value::<Request>(serde_json::json!({
            "operation": "prepare_bridge",
            "instance_id": "instance",
            "vm_id": "vm",
            "nic_index": 0,
            "bridge": "br0",
            "mac": "02:00:00:00:00:01",
            "qemu_uid": 1000,
            "filtered": true,
        }))
        .unwrap_err();
        assert!(error.to_string().contains("queues"), "{error}");
        assert_eq!(validate_queues(0).unwrap(), 1);
    }

    #[test]
    fn macvtap_prepare_has_a_dedicated_operation() {
        let request = Request::PrepareMacvtap(PrepareMacvtapRequest {
            identity: identity("instance", "vm", 1),
            parent: "eth0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            mode: "private".into(),
            queues: 0,
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
            filtered: true,
            queues: 0,
        });
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["operation"], "prepare_bridge");
        assert_eq!(value["instance_id"], "instance");
        assert_eq!(value["bridge"], "br0");
        assert!(value.get("identity").is_none());
    }

    /// Connecting and closing without sending is how the VMM checks that netd
    /// is alive, because a netd that died leaves its socket behind. It has to
    /// be handled promptly, and quietly: the VMM does it once per status query
    /// that mentions a stopped VM, and netd's accept loop is serialized, so
    /// treating a probe as a failed request would both fill the log and put
    /// noise in front of real work.
    #[tokio::test]
    async fn a_connection_that_sends_nothing_is_a_liveness_probe() {
        let (mut server, client) = UnixStream::pair().unwrap();
        drop(client);
        let result = timeout(
            Duration::from_secs(1),
            serve_connection(&NetdConfig::default(), &mut server),
        )
        .await;
        assert!(result.is_ok(), "disconnected peer blocked the handler");
        assert!(result.unwrap().is_ok(), "a probe is not a failed request");
    }

    /// Only an empty connection is a probe. A peer that does send something,
    /// and sends nonsense, is still a request -- and still gets an answer it
    /// can read, which is how a VMM newer than its netd learns to say so.
    #[tokio::test]
    async fn a_request_that_cannot_be_understood_still_gets_an_answer() {
        let (mut server, client) = UnixStream::pair().unwrap();
        drop(client);
        assert!(read_request(&mut server).await.unwrap().is_none());

        let (mut server, mut client) = UnixStream::pair().unwrap();
        // An operation only a newer VMM knows about.
        client
            .write_all(br#"{"operation":"prepare_something_new"}"#)
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        serve_connection(&NetdConfig::default(), &mut server)
            .await
            .unwrap();

        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(reply["ok"], false);
        assert!(
            reply["error"].as_str().unwrap().contains("unknown variant"),
            "{reply}"
        );
    }

    /// netd is the privileged side of this socket. "Build me a TAP on br0 with
    /// no nwfilter binding" is the request the boundary exists to refuse on a
    /// filtering node, and before this the daemon simply did what it was told,
    /// leaving the invariant with the unprivileged caller.
    #[test]
    fn a_filtering_node_refuses_an_unfiltered_bridge_tap() {
        let request = PrepareBridgeRequest {
            identity: InterfaceIdentity {
                instance_id: "i".into(),
                vm_id: "v".into(),
                nic_index: 0,
            },
            // A name no host has, so the check after this one is the one that
            // fails when this one does not.
            bridge: "dstack-nobr0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: false,
            queues: 4,
        };
        let filtering = NetworkFilterConfig {
            mode: crate::config::NetworkFilterMode::Libvirt,
            ..NetworkFilterConfig::default()
        };
        let error = validate_prepare_bridge(&request, &filtering).unwrap_err();
        assert!(
            error.to_string().contains("requires an nwfilter binding"),
            "{error}"
        );

        // An unfiltered node still builds them; that is what multiqueue needs.
        // It gets as far as asking the host about the bridge, which is the
        // next check and not this one's business.
        let error = validate_prepare_bridge(&request, &NetworkFilterConfig::default()).unwrap_err();
        assert!(
            error.to_string().contains("is not a host bridge"),
            "{error}"
        );
    }

    /// nwfilter does not apply to macvtap, and a macvtap parent may be the very
    /// bridge the policy protects. Refusing an unfiltered bridge TAP while
    /// handing out a macvtap on the same segment would leave the policy
    /// enforced only against the spelling that happens to be checked.
    #[test]
    fn a_filtering_node_refuses_a_macvtap_parent_that_is_a_bridge() {
        let filtering = NetworkFilterConfig {
            mode: crate::config::NetworkFilterMode::Libvirt,
            ..NetworkFilterConfig::default()
        };
        let bridges: Vec<String> = std::fs::read_dir("/sys/class/net")
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().join("bridge").exists())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        let Some(bridge) = bridges.first() else {
            // Nothing to assert against on a host with no bridge; the unit
            // below still pins the enslaved case's sysfs predicate.
            return;
        };
        let request = PrepareMacvtapRequest {
            identity: identity("i", "v", 0),
            parent: bridge.clone(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            mode: "bridge".into(),
            queues: 4,
        };
        let error = match prepare_macvtap("test:///default", &request, &filtering) {
            Err(error) => error,
            Ok(_) => panic!("a filtering node must not build a macvtap on a host bridge"),
        };
        assert!(error.to_string().contains("is a host bridge"), "{error}");
    }

    /// The request says whether to bind a filter, never which one. `allow-arp`
    /// contains no drop rule at all, and `clean-traffic` pinned to the
    /// gateway's MAC and IP through its parameters filters nothing useful
    /// either -- both would satisfy a policy that only asked for "some filter".
    #[test]
    fn the_bound_filter_comes_from_netds_own_configuration() {
        let request = PrepareBridgeRequest {
            identity: identity("i", "v", 0),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: true,
            queues: 1,
        };
        // Nothing on the wire can name a filter: the field does not exist.
        let wire = serde_json::to_value(Request::PrepareBridge(request.clone())).unwrap();
        assert!(wire.get("filter").is_none(), "{wire}");
        assert!(wire.get("parameters").is_none(), "{wire}");

        let policy = NetworkFilterConfig {
            mode: crate::config::NetworkFilterMode::Libvirt,
            filter: "clean-traffic".into(),
            parameters: BTreeMap::from([("IP".into(), "10.0.0.2".into())]),
        };
        let xml = binding_xml(&request, "dt123", &policy);
        assert!(xml.contains("filter='clean-traffic'"), "{xml}");
        assert!(xml.contains("value='10.0.0.2'"), "{xml}");
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
