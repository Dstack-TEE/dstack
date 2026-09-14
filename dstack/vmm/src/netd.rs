// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Small privileged broker for TAP creation and libvirt nwfilter bindings.
//!
//! netd serves the `Netd` pRPC service (see `netd-rpc/proto/netd_rpc.proto`)
//! over a Unix socket. Each operation is its own RPC method with its own
//! request and response messages.

use std::{
    fs::{File, OpenOptions, Permissions},
    io::{self, Write as _},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::UnixStream as StdUnixStream,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use http_client::{prpc::PrpcClient, ConnectionReuse};
use listenfd::ListenFd;
use ra_rpc::{CallContext, RpcCall};
use rocket::listener::{unix::UnixStream as RocketUnixStream, Endpoint, Listener};
use sha2::{Digest, Sha256};
use tokio::net::UnixListener;
use tracing::{info, warn};
use uuid::Uuid;
use wait_timeout::ChildExt;

use dstack_netd_rpc::netd_server::{NetdRpc, NetdServer};
pub use dstack_netd_rpc::{
    netd_client::NetdClient, CheckInterfaceRequest, InterfaceIdentity, PrepareBridgeRequest,
    PrepareMacvtapRequest, PreparedInterface,
};

use crate::config::{NetdConfig, NetworkFilterConfig};

/// Bounds a whole call from the VMM, including waiting for netd to finish the
/// operations queued ahead of it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const IP_PATH: &str = "/usr/sbin/ip";
const VIRSH_PATH: &str = "/usr/bin/virsh";
const LOCK_PATH: &str = "/run/lock/dstack-netd.lock";
/// Upper bound on TAP queue pairs netd will create. Mirrors the VMM's own cap
/// so a malformed request cannot ask the kernel for an unbounded device.
const MAX_QUEUES: u32 = 64;

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

/// A client for the netd listening at `socket`.
///
/// Every call opens its own connection. netd may have been restarted since the
/// last one, and a pooled connection to the previous process would fail a
/// request that a fresh one would have delivered.
pub fn client(socket: &Path) -> NetdClient<PrpcClient> {
    NetdClient::new(
        PrpcClient::new_unix(socket.display().to_string(), "/prpc".into())
            .with_connection_reuse(ConnectionReuse::Fresh)
            .with_request_timeout(REQUEST_TIMEOUT),
    )
}

/// Whether this error means netd was never reached.
///
/// Only the two errnos that mean "nothing is listening". A socket the VMM's
/// user cannot open (`EACCES`) or a VMM out of descriptors is a different
/// problem, and must not be reported as a missing netd.
pub fn is_unreachable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            )
        })
    })
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
    // Access is authorized by the Unix socket's owner, group, and mode. Any
    // process that can connect is trusted with every netd method.
    // Rocket's defaults only: a root daemon should not pick up a `Rocket.toml`
    // from its working directory or `ROCKET_*` variables from its environment.
    let figment = rocket::figment::Figment::from(rocket::Config::default())
        .merge(("ident", false))
        .merge(("cli_colors", false));
    let ignite = rocket::custom(figment)
        .manage(NetdState::new(config, LOCK_PATH.into()))
        .mount("/prpc", ra_rpc::prpc_routes!(NetdState, NetdHandler))
        .ignite()
        .await
        .map_err(|error| anyhow!("failed to ignite netd: {error}"))?;
    ignite
        .launch_on(NetdListener(listener))
        .await
        .map_err(|error| anyhow!("netd server failed: {error}"))?;
    Ok(())
}

/// Adapts the socket netd bound, or was handed by systemd, to Rocket.
struct NetdListener(UnixListener);

impl Listener for NetdListener {
    type Accept = RocketUnixStream;
    type Connection = RocketUnixStream;

    async fn accept(&self) -> io::Result<Self::Accept> {
        Ok(self.0.accept().await?.0)
    }

    async fn connect(&self, accept: Self::Accept) -> io::Result<Self::Connection> {
        Ok(accept)
    }

    fn endpoint(&self) -> io::Result<Endpoint> {
        self.0.local_addr()?.try_into()
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
        let _lock = OperationLock::acquire(Path::new(LOCK_PATH))?;
        prepare_socket_path(&config.socket)?;
        UnixListener::bind(&config.socket)
            .with_context(|| format!("failed to bind netd socket {}", config.socket.display()))?
    };
    std::fs::set_permissions(&config.socket, Permissions::from_mode(config.socket_mode))?;
    Ok(listener)
}

pub struct NetdState {
    config: Arc<NetdConfig>,
    /// Runs operations one at a time, in the order they arrived.
    ///
    /// The VMM relies on that order: after a Prepare times out on its side it
    /// sends a removal for the same interface, which must run after the
    /// Prepare it undoes rather than before it. Tokio's mutex queues waiters
    /// fairly. [`OperationLock`] still serializes against other netd
    /// processes, but an flock gives no ordering between its waiters.
    serial: Arc<tokio::sync::Mutex<()>>,
    lock_path: Arc<PathBuf>,
}

impl NetdState {
    fn new(config: NetdConfig, lock_path: PathBuf) -> Self {
        Self {
            config: Arc::new(config),
            serial: Arc::new(tokio::sync::Mutex::new(())),
            lock_path: Arc::new(lock_path),
        }
    }
}

pub struct NetdHandler {
    config: Arc<NetdConfig>,
    serial: Arc<tokio::sync::Mutex<()>>,
    lock_path: Arc<PathBuf>,
}

impl RpcCall<NetdState> for NetdHandler {
    type PrpcService = NetdServer<Self>;

    fn construct(context: CallContext<'_, NetdState>) -> Result<Self> {
        Ok(Self {
            config: context.state.config.clone(),
            serial: context.state.serial.clone(),
            lock_path: context.state.lock_path.clone(),
        })
    }
}

impl NetdHandler {
    /// Runs one host operation under both locks.
    ///
    /// The operations shell out to `ip` and `virsh` and wait on them, so they
    /// run on the blocking pool. The queue slot moves into that task: if the
    /// request future is dropped, the next operation still waits for this one
    /// to finish instead of starting beside it.
    async fn run<T, F>(self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&NetdConfig) -> Result<T> + Send + 'static,
    {
        let slot = self.serial.lock_owned().await;
        let config = self.config;
        let lock_path = self.lock_path;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let _lock = OperationLock::acquire(&lock_path)?;
            operation(&config)
        })
        .await
        .context("netd operation task failed")?
    }
}

impl NetdRpc for NetdHandler {
    async fn prepare_bridge(self, request: PrepareBridgeRequest) -> Result<PreparedInterface> {
        self.run(move |config| {
            prepare_bridge(&config.libvirt_uri, &request, config.filter_policy())
        })
        .await
    }

    async fn prepare_macvtap(self, request: PrepareMacvtapRequest) -> Result<PreparedInterface> {
        self.run(move |config| {
            prepare_macvtap(&config.libvirt_uri, &request, config.filter_policy())
        })
        .await
    }

    async fn remove_interface(self, identity: InterfaceIdentity) -> Result<()> {
        self.run(move |config| {
            validate_identity(&identity)?;
            let tap = tap_name(&identity);
            // Best effort about the binding, whatever was built. The strict
            // rule exists for prepare, where a binding left at the name would
            // block the one about to be created; at removal nothing is about
            // to take the name, and failing here would leave the interface
            // itself up on the bridge rather than just a stale binding.
            remove_interface(&config.libvirt_uri, &tap, BindingCleanup::BestEffort)
        })
        .await
    }

    async fn check_interface(self, request: CheckInterfaceRequest) -> Result<()> {
        self.run(move |config| {
            let identity = required_identity(&request.identity)?;
            let tap = tap_name(identity);
            if !Path::new("/sys/class/net").join(&tap).exists() {
                bail!("TAP {tap} does not exist");
            }
            // An unfiltered TAP has no binding to dump; asking for one would
            // report a healthy multiqueue interface as broken.
            if request.filtered && !is_macvtap(&tap) {
                virsh(
                    &config.libvirt_uri,
                    &["nwfilter-binding-dumpxml", &tap],
                    None,
                )?;
            }
            Ok(())
        })
        .await
    }
}

/// The identity a request names, validated.
///
/// Message fields are optional on the wire, and an interface name derived from
/// a missing identity would name some interface nobody asked for.
fn required_identity(identity: &Option<InterfaceIdentity>) -> Result<&InterfaceIdentity> {
    let identity = identity
        .as_ref()
        .context("request does not name an interface identity")?;
    validate_identity(identity)?;
    Ok(identity)
}

fn prepare_macvtap(
    libvirt_uri: &str,
    request: &PrepareMacvtapRequest,
    filter: &NetworkFilterConfig,
) -> Result<PreparedInterface> {
    let identity = required_identity(&request.identity)?;
    let parent = request.parent.as_str();
    let qemu_uid = request.qemu_uid;
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
            Ok(PreparedInterface {
                tap,
                device,
                queues,
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
    fn acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
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
) -> Result<PreparedInterface> {
    let identity = validate_prepare_bridge(request, filter)?;
    let filtered = request.filtered;
    let tap = tap_name(identity);
    // A failed VMM start may leave a deterministic resource behind. Replacing
    // it makes prepare idempotent without accepting a caller-selected TAP.
    // A binding outlives the interface it was bound to and TAP names are
    // derived, so the same name comes back: clear whatever is there. Insist
    // only when this prepare is about to create a replacement libvirt would
    // refuse as a duplicate.
    remove_interface(
        libvirt_uri,
        &tap,
        if filtered {
            BindingCleanup::Required
        } else {
            BindingCleanup::BestEffort
        },
    )?;

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
            let xml = binding_xml(identity, &request.mac, &tap, filter);
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
    Ok(PreparedInterface {
        tap,
        device: String::new(),
        queues,
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
/// call. netd runs one operation at a time, so an unbounded call here
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

fn binding_xml(
    identity: &InterfaceIdentity,
    mac: &str,
    tap: &str,
    filter: &NetworkFilterConfig,
) -> String {
    let owner_uuid = stable_uuid(identity);
    let owner_name = format!(
        "dstack:{}:{}:{}",
        identity.instance_id, identity.vm_id, identity.nic_index
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
        xml_escape(mac),
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

/// Validates a bridge prepare and returns the identity it names.
fn validate_prepare_bridge<'a>(
    request: &'a PrepareBridgeRequest,
    filter: &NetworkFilterConfig,
) -> Result<&'a InterfaceIdentity> {
    let identity = required_identity(&request.identity)?;
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
    Ok(identity)
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

    fn identity(instance: &str, vm: &str, nic_index: u32) -> InterfaceIdentity {
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
            identity: Some(identity("instance<&", "vm", 0)),
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
        let xml = binding_xml(
            request.identity.as_ref().unwrap(),
            &request.mac,
            "dt123",
            &filter,
        );
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
    fn queue_counts_normalize_to_at_least_one_and_stay_bounded() {
        assert_eq!(validate_queues(0).unwrap(), 1);
        assert_eq!(validate_queues(1).unwrap(), 1);
        assert_eq!(validate_queues(MAX_QUEUES).unwrap(), MAX_QUEUES);
        assert!(validate_queues(MAX_QUEUES + 1).is_err());
    }

    /// netd is the privileged side of this socket. "Build me a TAP on br0 with
    /// no nwfilter binding" is the request the boundary exists to refuse on a
    /// filtering node, and before this the daemon simply did what it was told,
    /// leaving the invariant with the unprivileged caller.
    #[test]
    fn a_filtering_node_refuses_an_unfiltered_bridge_tap() {
        let request = PrepareBridgeRequest {
            identity: Some(identity("i", "v", 0)),
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
            identity: Some(identity("i", "v", 0)),
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
            identity: Some(identity("i", "v", 0)),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: true,
            queues: 1,
        };
        // Nothing on the wire can name a filter: the field does not exist.
        let wire = serde_json::to_value(&request).unwrap();
        assert!(wire.get("filter").is_none(), "{wire}");
        assert!(wire.get("parameters").is_none(), "{wire}");

        let policy = NetworkFilterConfig {
            mode: crate::config::NetworkFilterMode::Libvirt,
            filter: "clean-traffic".into(),
            parameters: BTreeMap::from([("IP".into(), "10.0.0.2".into())]),
        };
        let xml = binding_xml(
            request.identity.as_ref().unwrap(),
            &request.mac,
            "dt123",
            &policy,
        );
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

    /// The VMM tells "netd is not running" apart from "netd refused". Both
    /// ways a Unix socket can have nobody behind it must read as the former,
    /// through the context the pRPC client stacks on the transport error.
    #[tokio::test]
    async fn a_socket_with_no_netd_behind_it_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();

        let missing = dir.path().join("missing.sock");
        let error = client(&missing)
            .remove_interface(identity("i", "v", 0))
            .await
            .unwrap_err();
        assert!(is_unreachable(&error), "{error:#}");

        // A socket file left behind by a netd that exited.
        let stale = dir.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
        let error = client(&stale)
            .remove_interface(identity("i", "v", 0))
            .await
            .unwrap_err();
        assert!(is_unreachable(&error), "{error:#}");

        let refused = anyhow::anyhow!("this netd requires an nwfilter binding on every bridge TAP");
        assert!(!is_unreachable(&refused));
    }

    /// After a Prepare times out on the VMM's side, the VMM removes the same
    /// interface. That removal must run after the Prepare, not beside or
    /// before it, or the Prepare would leave behind the interface the removal
    /// was sent to delete.
    #[tokio::test]
    async fn operations_run_one_at_a_time_in_arrival_order() {
        let dir = tempfile::tempdir().unwrap();
        let state = NetdState::new(NetdConfig::default(), dir.path().join("netd.lock"));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for index in 0..8 {
            let handler = NetdHandler {
                config: state.config.clone(),
                serial: state.serial.clone(),
                lock_path: state.lock_path.clone(),
            };
            let order = order.clone();
            tasks.push(tokio::spawn(handler.run(move |_| {
                order.lock().unwrap().push((index, "start"));
                // Long enough that a later operation running beside this one
                // would interleave with it.
                std::thread::sleep(Duration::from_millis(if index == 0 { 100 } else { 5 }));
                order.lock().unwrap().push((index, "end"));
                Ok(())
            })));
            // Let this request take its place in the queue before the next
            // one arrives.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        let expected: Vec<_> = (0..8).flat_map(|i| [(i, "start"), (i, "end")]).collect();
        assert_eq!(*order.lock().unwrap(), expected);
    }

    /// Serves netd's routes on a temporary socket, without the root and host
    /// tool checks `serve` makes.
    async fn spawn_test_netd(dir: &Path) -> PathBuf {
        let socket = dir.join("netd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let ignite = rocket::custom(rocket::Config::figment().merge(("log_level", "off")))
            .manage(NetdState::new(NetdConfig::default(), dir.join("netd.lock")))
            .mount("/prpc", ra_rpc::prpc_routes!(NetdState, NetdHandler))
            .ignite()
            .await
            .unwrap();
        tokio::spawn(ignite.launch_on(NetdListener(listener)));
        socket
    }

    /// A refusal has to reach the VMM with netd's reason in it: that reason is
    /// what an operator acts on, and a bare status code names nothing.
    #[tokio::test]
    async fn a_refused_request_reaches_the_caller_with_netds_reason() {
        let dir = tempfile::tempdir().unwrap();
        let socket = spawn_test_netd(dir.path()).await;

        // Refused by validation, before any host tool runs.
        let error = client(&socket)
            .check_interface(CheckInterfaceRequest {
                identity: None,
                filtered: false,
            })
            .await
            .unwrap_err();
        assert!(!is_unreachable(&error), "{error:#}");
        assert!(
            format!("{error:#}").contains("does not name an interface identity"),
            "{error:#}"
        );

        let error = client(&socket)
            .remove_interface(identity("", "v", 0))
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("invalid instance ID"),
            "{error:#}"
        );
    }
}
