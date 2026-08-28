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
/// Bumped when the protocol gains an operation or a field a caller must know
/// about. `Hello` reports it so a VMM newer than its netd learns that once, at
/// startup, instead of one failed operation at a time.
const PROTOCOL_VERSION: u32 = 1;
/// Named capabilities, so a caller can ask about one feature without mapping
/// version numbers onto it. A netd that predates `Hello` answers with an error
/// rather than a list, which reads as "none of these".
const FEATURES: &[&str] = &["multiqueue", "list"];
/// Stamped into the TAP's `ifalias` so `List` can tell one VMM instance's
/// interfaces from another's. The identity itself is not recorded: the caller
/// derives every TAP name it owns from `tap_name`, so the namespace is the only
/// part it cannot work out for itself.
const ALIAS_PREFIX: &str = "dstack-netd:1:";
/// The kernel's `IFALIAS_MAX`, including the terminator.
const MAX_IFALIAS: usize = 255;

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
    /// The VM's working directory on the host, for logs and diagnostics.
    ///
    /// Untrusted and never read for a decision: the caller asserts it, and any
    /// process that can reach the socket can assert anything. It is here so an
    /// operator reading netd's log can get from an opaque TAP name back to the
    /// VM that asked for it without going through the VMM.
    #[serde(default)]
    pub workdir: String,
    /// Host ports this VM wants reachable at its guest.
    ///
    /// Empty asks for nothing, which is what a caller that predates the field
    /// sends. A netd that does not implement forwarding refuses a non-empty
    /// list rather than building the interface without it: the alternative is
    /// the failure this field exists to end, where ports are accepted, reported
    /// back, and silently never forwarded.
    #[serde(default)]
    pub ingress: Vec<IngressRequest>,
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
    /// The VM's working directory on the host. Informational only; see
    /// [`PrepareBridgeRequest::workdir`].
    #[serde(default)]
    pub workdir: String,
}

/// One host port a VM wants reachable at its guest.
///
/// The caller names every field. That is the same treatment `bridge`, `mac` and
/// `queues` get, and the opposite of `filtered`: an nwfilter name cannot be
/// checked for whether it filters anything, so naming one is excluded, while a
/// host port is a closed space netd can check a request against. Naming is not
/// deciding -- which ports may be handed out, and to whom, stays netd's own
/// configuration, exactly as `allowed_bridges` governs the bridge a caller
/// names.
///
/// The VMM does not implement forwarding for these. It carries the requirement
/// to whoever configures the host, because the VMM runs without
/// `CAP_NET_ADMIN` by design, and because netd is the only component that sees
/// every VMM instance on the host and can therefore arbitrate a host port
/// between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressRequest {
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    /// Host address to accept on. Empty leaves the choice to netd.
    ///
    /// Not merely cosmetic: an admin or metrics port bound to loopback and one
    /// published to the world differ only here, and a forwarder that dropped
    /// the distinction would publish the first.
    #[serde(default)]
    pub host_address: String,
    /// Host port. Zero asks netd to choose from whatever range it allocates.
    pub host_port: u16,
    pub guest_port: u16,
}

/// One forwarding rule netd established, echoed so the caller can report what
/// the VM actually got rather than what it asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressBinding {
    pub protocol: String,
    pub host_address: String,
    pub host_port: u16,
    pub guest_port: u16,
}

/// A netd-managed interface as `List` found it on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedInterface {
    pub tap: String,
    /// The bridge this TAP is enslaved to, if any. A macvtap has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master: Option<String>,
    /// `"tap"` or `"macvtap"`.
    pub kind: String,
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
    /// Report the protocol version and feature names this netd implements.
    ///
    /// Every field added so far has been detected by its own absence from a
    /// response -- `queues` is documented that way. That works once per field
    /// and only for fields that are echoed back, and netd ships as a separate
    /// package on its own release cadence, so version skew is the normal case
    /// rather than the exception. Asking once beats inferring repeatedly.
    Hello {},
    /// Enumerate the interfaces netd holds for one VMM instance.
    ///
    /// netd creates persistent TAPs, so a VMM that died between creating one
    /// and recording it leaks an interface that nothing can find again: `Check`
    /// answers about an identity the caller must already know. Listing is
    /// scoped to an instance namespace because a host can run several VMMs, and
    /// a caller reconciling its own VMs must not mistake another's interfaces
    /// for orphans.
    List {
        instance_id: String,
    },
    /// Remove an interface by name rather than by identity.
    ///
    /// The name must be one netd itself could have generated, so this reaches
    /// nothing it did not create. It exists for the orphan `List` reports: its
    /// identity is exactly what the caller no longer has, and the identity is
    /// only ever used to derive this name.
    RemoveTap {
        tap: String,
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
    /// Protocol version, answering `Hello`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<u32>,
    /// Feature names, answering `Hello`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    features: Option<Vec<String>>,
    /// Managed interfaces, answering `List`. Present and empty means netd holds
    /// none; absent means it did not understand the question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interfaces: Option<Vec<ManagedInterface>>,
    /// The address this NIC will reach the segment at, when netd is the one
    /// that decides it.
    ///
    /// A DNAT rule needs an address at install time and a DHCP lease does not
    /// exist until the guest has booted, so a netd that forwards ports is
    /// necessarily also the authority on the address. Reporting it back is what
    /// lets the VMM show a bridge VM's address without a lease callback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_ip: Option<String>,
    /// Forwarding rules netd established. Absent from a netd that does not
    /// implement forwarding, which is how the caller tells "nothing was asked
    /// for" apart from "this was ignored".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress: Option<Vec<IngressBinding>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    /// A response that claims nothing, so each arm below states only the fields
    /// its own operation answers with.
    fn empty() -> Self {
        Self {
            ok: false,
            tap: None,
            device: None,
            queues: None,
            version: None,
            features: None,
            interfaces: None,
            guest_ip: None,
            ingress: None,
            error: None,
        }
    }
}

/// What netd built, echoed back so the caller can verify it matches the
/// request before handing the interface to QEMU.
struct Prepared {
    tap: String,
    device: Option<String>,
    queues: Option<u32>,
    guest_ip: Option<String>,
    ingress: Option<Vec<IngressBinding>>,
}

impl Prepared {
    fn tap(tap: String) -> Self {
        Self {
            tap,
            device: None,
            queues: None,
            guest_ip: None,
            ingress: None,
        }
    }
}

/// What a request produced. Every operation used to name an interface, so the
/// response shape could be flat; `Hello` and `List` answer about netd itself.
enum Outcome {
    Interface(Prepared),
    Capabilities,
    Interfaces(Vec<ManagedInterface>),
}

/// What a netd reported about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub version: u32,
    pub features: Vec<String>,
}

impl Capabilities {
    /// What a netd that predates `Hello` amounts to: reachable, but claiming
    /// nothing. Version zero is not a version netd ever reported, so it cannot
    /// be confused with one that answered.
    pub fn legacy() -> Self {
        Self {
            version: 0,
            features: Vec::new(),
        }
    }

    pub fn has(&self, feature: &str) -> bool {
        self.features.iter().any(|name| name == feature)
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

/// Whether a name has the shape [`tap_name`] produces.
///
/// This is what keeps removal by name from reaching an interface netd did not
/// create: the caller names one, and a name outside this shape is refused
/// before anything runs.
pub fn is_managed_tap_name(name: &str) -> bool {
    let Some(digest) = name.strip_prefix("dt") else {
        return false;
    };
    digest.len() == 12
        && digest
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_uppercase())
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
    /// The address netd says this NIC will use, when netd decides addresses.
    pub guest_ip: Option<String>,
    /// The forwarding rules netd established, if it establishes any.
    pub ingress: Option<Vec<IngressBinding>>,
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
    let response = exchange(socket, request).await?;
    response.tap.context("netd response omitted TAP name")?;
    Ok(PreparedInterface {
        device: response.device,
        queues: response.queues,
        guest_ip: response.guest_ip,
        ingress: response.ingress,
    })
}

/// Asks netd what it implements.
///
/// A netd that predates `Hello` rejects the operation, which is not a failure
/// to report: it is the answer. Only an unreachable netd is an error, because
/// the caller asked about a daemon and got no daemon.
pub async fn capabilities(socket: &Path) -> Result<Capabilities> {
    match exchange(socket, &Request::Hello {}).await {
        Ok(response) => Ok(Capabilities {
            version: response.version.unwrap_or_default(),
            features: response.features.unwrap_or_default(),
        }),
        Err(error) if is_unreachable(&error) => Err(error),
        Err(error) => {
            debug!(%error, "netd does not report capabilities");
            Ok(Capabilities::legacy())
        }
    }
}

/// Lists the interfaces netd holds for one VMM instance.
pub async fn list(socket: &Path, instance_id: &str) -> Result<Vec<ManagedInterface>> {
    let request = Request::List {
        instance_id: instance_id.to_string(),
    };
    exchange(socket, &request)
        .await?
        .interfaces
        .context("netd response omitted the interface list")
}

/// Removes an interface by name. See [`Request::RemoveTap`].
pub async fn remove_tap(socket: &Path, tap: &str) -> Result<()> {
    let request = Request::RemoveTap {
        tap: tap.to_string(),
    };
    exchange(socket, &request).await.map(drop)
}

async fn exchange(socket: &Path, request: &Request) -> Result<Response> {
    let operation = match request {
        Request::PrepareBridge(_) => "prepare_bridge",
        Request::PrepareMacvtap(_) => "prepare_macvtap",
        Request::Remove { .. } => "remove",
        Request::Check { .. } => "check",
        Request::Hello {} => "hello",
        Request::List { .. } => "list",
        Request::RemoveTap { .. } => "remove_tap",
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
        Ok(response)
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
        Ok(Outcome::Interface(prepared)) => Response {
            ok: true,
            tap: Some(prepared.tap),
            device: prepared.device,
            queues: prepared.queues,
            guest_ip: prepared.guest_ip,
            ingress: prepared.ingress,
            ..Response::empty()
        },
        Ok(Outcome::Capabilities) => Response {
            ok: true,
            version: Some(PROTOCOL_VERSION),
            features: Some(FEATURES.iter().map(|name| name.to_string()).collect()),
            ..Response::empty()
        },
        Ok(Outcome::Interfaces(interfaces)) => Response {
            ok: true,
            interfaces: Some(interfaces),
            ..Response::empty()
        },
        Err(error) => {
            warn!(%error, "netd request failed");
            Response {
                error: Some(format!("{error:#}")),
                ..Response::empty()
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

fn handle_request(config: &NetdConfig, request: Request) -> Result<Outcome> {
    let libvirt_uri = config.libvirt_uri.as_str();
    let _lock = OperationLock::acquire()?;
    match request {
        Request::PrepareBridge(request) => {
            prepare_bridge(libvirt_uri, &request, config.filter_policy()).map(Outcome::Interface)
        }
        Request::PrepareMacvtap(request) => {
            prepare_macvtap(libvirt_uri, &request, config.filter_policy()).map(Outcome::Interface)
        }
        Request::Hello {} => Ok(Outcome::Capabilities),
        Request::List { instance_id } => list_interfaces(&instance_id).map(Outcome::Interfaces),
        Request::RemoveTap { tap } => {
            if !is_managed_tap_name(&tap) {
                bail!("{tap} is not a name netd creates");
            }
            // The caller reached this operation because it lost the identity,
            // so it cannot say whether a binding was ever bound. Clearing one
            // best-effort is right in both directions: a leftover binding would
            // be inherited by the next interface to take this name, and a node
            // running unfiltered TAPs need not have libvirtd at all.
            remove_interface(libvirt_uri, &tap, BindingCleanup::BestEffort)?;
            Ok(Outcome::Interface(Prepared::tap(tap)))
        }
        Request::Remove { identity, filtered } => {
            validate_identity(&identity)?;
            let tap = tap_name(&identity);
            remove_interface(libvirt_uri, &tap, binding_cleanup(filtered))?;
            Ok(Outcome::Interface(Prepared::tap(tap)))
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
            Ok(Outcome::Interface(Prepared::tap(tap)))
        }
    }
}

/// Records which VMM instance owns a TAP, in the kernel rather than in a file.
///
/// netd derives every other fact it needs from the request or from sysfs, and a
/// state file would be one more thing to keep true across a crash. The identity
/// is deliberately not stored: `ifalias` holds 255 bytes and two 128-byte
/// identifiers do not fit, and the caller can already derive every TAP name it
/// owns. The namespace is the only part it cannot.
fn stamp_namespace(tap: &str, instance_id: &str) -> Result<()> {
    let Some(alias) = namespace_alias(instance_id) else {
        // Leaving it unstamped is not a failure worth refusing the interface
        // over: the VM works, and only reconciliation is degraded, which leaves
        // the TAP unattributed rather than deleting it.
        warn!(%tap, "instance ID is too long to record on the interface");
        return Ok(());
    };
    ip(&["link", "set", "dev", tap, "alias", &alias])
}

/// The alias for a namespace, or `None` when the kernel could not hold it.
fn namespace_alias(instance_id: &str) -> Option<String> {
    let alias = format!("{ALIAS_PREFIX}{instance_id}");
    (alias.len() < MAX_IFALIAS).then_some(alias)
}

/// Reads back what [`stamp_namespace`] wrote, if anything.
fn namespace_of(tap: &str) -> Option<String> {
    let alias =
        std::fs::read_to_string(Path::new("/sys/class/net").join(tap).join("ifalias")).ok()?;
    alias
        .trim_end_matches('\n')
        .strip_prefix(ALIAS_PREFIX)
        .map(ToOwned::to_owned)
}

fn list_interfaces(instance_id: &str) -> Result<Vec<ManagedInterface>> {
    if instance_id.is_empty() || instance_id.len() > 128 || instance_id.contains('\0') {
        bail!("invalid instance ID");
    }
    let mut interfaces = Vec::new();
    let entries = std::fs::read_dir("/sys/class/net").context("failed to list host interfaces")?;
    for entry in entries {
        let entry = entry.context("failed to read a host interface entry")?;
        let Ok(tap) = entry.file_name().into_string() else {
            continue;
        };
        // An interface whose name netd could not have produced is not netd's,
        // whatever its alias says.
        if !is_managed_tap_name(&tap) || namespace_of(&tap).as_deref() != Some(instance_id) {
            continue;
        }
        let master = std::fs::read_link(entry.path().join("master"))
            .ok()
            .and_then(|path| path.file_name()?.to_str().map(ToOwned::to_owned));
        let kind = if is_macvtap(&tap) { "macvtap" } else { "tap" };
        interfaces.push(ManagedInterface {
            tap,
            master,
            kind: kind.to_string(),
        });
    }
    interfaces.sort_by(|left, right| left.tap.cmp(&right.tap));
    Ok(interfaces)
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
        stamp_namespace(&tap, &identity.instance_id)?;
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
                guest_ip: None,
                ingress: None,
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
        stamp_namespace(&tap, &request.identity.instance_id)?;
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
        // This netd assigns no addresses and forwards no ports, so it has
        // nothing to report beyond the interface itself.
        guest_ip: None,
        ingress: None,
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
    // This netd creates interfaces; it is not the host's forwarder. Building
    // the TAP anyway and leaving the ports unforwarded is the silent failure
    // the field exists to end, so the request is refused whole. `hello` does
    // not name `ingress`, so a caller learns this before it ever asks.
    if !request.ingress.is_empty() {
        bail!(
            "this netd does not forward host ports, but {} was/were requested",
            request.ingress.len()
        );
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
            workdir: String::new(),
            ingress: Vec::new(),
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
            workdir: String::new(),
            ingress: Vec::new(),
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
            workdir: String::new(),
            ingress: Vec::new(),
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
            workdir: String::new(),
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
            workdir: String::new(),
            ingress: Vec::new(),
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
            workdir: String::new(),
            ingress: Vec::new(),
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
            workdir: String::new(),
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
            workdir: String::new(),
            ingress: Vec::new(),
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

    #[test]
    fn hello_reports_a_version_and_names_its_features() {
        let value = serde_json::to_value(Request::Hello {}).unwrap();
        assert_eq!(value["operation"], "hello");

        // A netd that predates this operation rejects it, and that rejection is
        // the answer rather than a failure: it claims no features.
        let legacy = Capabilities::legacy();
        assert_eq!(legacy.version, 0);
        assert!(!legacy.has("list"));

        // Every feature this netd implements has to be nameable, or a caller
        // has to map version numbers onto behaviour by hand.
        let reported = Capabilities {
            version: PROTOCOL_VERSION,
            features: FEATURES.iter().map(|name| name.to_string()).collect(),
        };
        assert!(reported.has("list"));
        assert!(reported.has("multiqueue"));
        assert!(!reported.has("ingress"));
    }

    #[test]
    fn listing_is_scoped_to_one_vmm_instance() {
        let value = serde_json::to_value(Request::List {
            instance_id: "instance".into(),
        })
        .unwrap();
        assert_eq!(value["operation"], "list");
        assert_eq!(value["instance_id"], "instance");

        // A host runs several VMMs against one netd. An unscoped list would
        // invite a caller to delete another VMM's interfaces as orphans.
        assert!(list_interfaces("").is_err());
        assert!(list_interfaces(&"x".repeat(129)).is_err());
    }

    #[test]
    fn removal_by_name_reaches_only_names_netd_could_have_made() {
        assert!(is_managed_tap_name(&tap_name(&identity(
            "instance", "vm", 0
        ))));
        for name in [
            "eth0",
            "dstack-br0",
            "dt",
            "dtnothex00000",
            "dtABCDEF012345",
        ] {
            assert!(!is_managed_tap_name(name), "{name}");
        }

        let value = serde_json::to_value(Request::RemoveTap { tap: "eth0".into() }).unwrap();
        assert_eq!(value["operation"], "remove_tap");
        assert_eq!(value["tap"], "eth0");
    }

    #[test]
    fn the_namespace_is_recorded_but_the_identity_is_not() {
        let instance = "path-0123456789abcdef";
        let alias = namespace_alias(instance).expect("a normal instance ID fits");
        assert!(alias.starts_with(ALIAS_PREFIX));
        assert_eq!(alias.strip_prefix(ALIAS_PREFIX), Some(instance));

        // `validate_identity` allows 128 bytes for each of two identifiers, and
        // two of those plus a prefix do not fit in IFALIAS_MAX. Recording only
        // the namespace does, and the caller derives its own TAP names anyway.
        assert!(namespace_alias(&"x".repeat(128)).is_some());
        assert!(namespace_alias(&"x".repeat(MAX_IFALIAS)).is_none());
    }

    #[test]
    fn the_workdir_is_carried_along_but_older_callers_may_omit_it() {
        let request = Request::PrepareBridge(PrepareBridgeRequest {
            identity: identity("instance", "vm", 0),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: true,
            queues: 1,
            workdir: "/opt/dstack/run/vm/vm".into(),
            ingress: Vec::new(),
        });
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["workdir"], "/opt/dstack/run/vm/vm");

        // It is a log line, not an input. A caller that never sets it is not
        // asking for anything different.
        let decoded = serde_json::from_value::<Request>(serde_json::json!({
            "operation": "prepare_bridge",
            "instance_id": "instance",
            "vm_id": "vm",
            "nic_index": 0,
            "bridge": "br0",
            "mac": "02:00:00:00:00:01",
            "qemu_uid": 1000,
            "filtered": true,
            "queues": 1,
        }))
        .unwrap();
        let Request::PrepareBridge(decoded) = decoded else {
            panic!("expected a bridge prepare");
        };
        assert_eq!(decoded.workdir, "");
    }

    #[test]
    fn ports_travel_with_the_bridge_prepare_and_default_to_none() {
        let request = Request::PrepareBridge(PrepareBridgeRequest {
            identity: identity("instance", "vm", 0),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: true,
            queues: 1,
            workdir: String::new(),
            ingress: vec![IngressRequest {
                protocol: "udp".into(),
                host_address: "0.0.0.0".into(),
                host_port: 7483,
                guest_port: 51820,
            }],
        });
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["ingress"][0]["protocol"], "udp");
        assert_eq!(value["ingress"][0]["host_port"], 7483);
        assert_eq!(value["ingress"][0]["guest_port"], 51820);
        // The bind address separates an admin port from a published one, so a
        // forwarder that lost it would publish the admin port.
        assert_eq!(value["ingress"][0]["host_address"], "0.0.0.0");

        // A caller that predates the field asks for nothing.
        let decoded = serde_json::from_value::<Request>(serde_json::json!({
            "operation": "prepare_bridge",
            "instance_id": "instance",
            "vm_id": "vm",
            "nic_index": 0,
            "bridge": "br0",
            "mac": "02:00:00:00:00:01",
            "qemu_uid": 1000,
            "filtered": true,
            "queues": 1,
        }))
        .unwrap();
        let Request::PrepareBridge(decoded) = decoded else {
            panic!("expected a bridge prepare");
        };
        assert!(decoded.ingress.is_empty());
    }

    #[test]
    fn a_netd_that_does_not_forward_refuses_the_ports_instead_of_dropping_them() {
        let mut request = PrepareBridgeRequest {
            identity: identity("instance", "vm", 0),
            bridge: "dt-absent-br".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: true,
            queues: 1,
            workdir: String::new(),
            ingress: vec![IngressRequest {
                protocol: "tcp".into(),
                host_address: "0.0.0.0".into(),
                host_port: 8443,
                guest_port: 443,
            }],
        };
        let filter = NetworkFilterConfig {
            mode: crate::config::NetworkFilterMode::Libvirt,
            filter: "clean-traffic".into(),
            parameters: Default::default(),
        };
        // Building the TAP and dropping the ports is the failure being ended,
        // so the whole request is refused -- and refused for the request's own
        // sake, before the host is inspected for a bridge that may not exist.
        let error = validate_prepare_bridge(&request, &filter).unwrap_err();
        assert!(
            error.to_string().contains("does not forward host ports"),
            "{error}"
        );

        // Asking for nothing gets past this check and on to the host, which is
        // where a bridge that does not exist is noticed.
        request.ingress.clear();
        request.bridge = "dt-absent-br".into();
        let error = validate_prepare_bridge(&request, &filter).unwrap_err();
        assert!(error.to_string().contains("not a host bridge"), "{error}");
    }

    #[test]
    fn a_forwarding_netd_is_not_this_one() {
        // `hello` is what tells a caller this before it asks, so the refusal
        // above is never the first thing it learns.
        assert!(!FEATURES.contains(&"ingress"));
    }
}
