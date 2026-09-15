// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Small privileged broker for TAP creation and libvirt nwfilter bindings.
//!
//! netd serves the `Netd` pRPC service (see `netd-rpc/proto/netd_rpc.proto`)
//! over a Unix socket. Each operation is its own RPC method with its own
//! request and response messages.

use std::{
    collections::HashSet,
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
use tracing::{debug, info, warn};
use uuid::Uuid;
use wait_timeout::ChildExt;

use dstack_netd_rpc::netd_server::{NetdRpc, NetdServer};
pub use dstack_netd_rpc::{
    netd_client::NetdClient, CheckInterfaceRequest, InterfaceIdentity, InterfaceList,
    InterfaceName, InterfaceRecord, ListInterfacesRequest, PrepareBridgeRequest,
    PrepareMacvtapRequest, PreparedInterface, RemoveVmResponse, VmRef,
};

use crate::config::{NetdConfig, NetworkFilterConfig};

/// Bounds a whole call from the VMM, including waiting for netd to finish the
/// operations queued ahead of it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on listing nwfilter bindings. See [`existing_bindings`].
const LISTING_TIMEOUT: Duration = Duration::from_secs(10);
const IP_PATH: &str = "/usr/sbin/ip";
const VIRSH_PATH: &str = "/usr/bin/virsh";
const LOCK_PATH: &str = "/run/lock/dstack-netd.lock";
/// Upper bound on TAP queue pairs netd will create. Mirrors the VMM's own cap
/// so a malformed request cannot ask the kernel for an unbounded device.
const MAX_QUEUES: u32 = 64;
/// Highest NIC index an identity may name. Also the width of the space a
/// whole-VM sweep has to enumerate, since it derives names instead of reading a
/// record.
const MAX_NIC_INDEX: u32 = 255;
/// The interface names netd may create. Reserved: anything matching it is
/// netd's to delete, and nothing else on the host may take one.
const TAP_PREFIX: &str = "dt";
/// Hex characters of digest in a TAP name, after [`TAP_PREFIX`].
const TAP_DIGEST_CHARS: usize = 12;
/// Version tag on the ownership record. Present so a later format can be told
/// from this one rather than mis-parsed as it.
const ALIAS_PREFIX: &str = "dstack1";
/// What the kernel stores in an interface alias, minus the terminator.
const MAX_IFALIAS: usize = 255;

pub fn tap_name(identity: &InterfaceIdentity) -> String {
    let input = format!(
        "{}\0{}\0{}",
        identity.instance_id, identity.vm_id, identity.nic_index
    );
    let digest = Sha256::digest(input.as_bytes());
    format!(
        "{TAP_PREFIX}{}",
        hex::encode(&digest[..TAP_DIGEST_CHARS / 2])
    )
}

/// The ownership record netd writes onto every interface it creates.
///
/// The record lives on the resource, so it has exactly the resource's
/// lifetime. A file under `/run` would be a second thing to keep in step with
/// the first, and the failure this whole path exists to fix is precisely a
/// record that got out of step: written after the interface, lost with the
/// directory, and unreadable to anything but the process that wrote it.
///
/// Never trusted as *authority*. Anything that can reach this socket can also
/// name an identity, and the interface name is a digest of that identity --
/// so a record is believed only when re-deriving the name from it reproduces
/// the name it is written on. Ambiguity (a separator inside an identity),
/// truncation, and forgery all fail that check and land in the same bucket as
/// no record at all, which is the bucket handled conservatively.
pub fn interface_alias(identity: &InterfaceIdentity) -> String {
    format!(
        "{ALIAS_PREFIX}:{}:{}:{}",
        identity.nic_index, identity.instance_id, identity.vm_id
    )
}

/// The identity an interface claims, if the claim checks out.
///
/// `nic_index` first, so the two free-form fields are the last two and a
/// `vm_id` containing the separator still parses. An `instance_id` containing
/// one does not, and is refused at prepare rather than mis-parsed here.
pub fn owner_of(tap: &str, alias: &str) -> Option<InterfaceIdentity> {
    // `trim_end_matches`, not `trim`: sysfs adds a newline, and a `vm_id`
    // whose own trailing whitespace were trimmed off here would re-derive a
    // name that is not the one it is on, making the interface permanently
    // unattributable -- never collected, only removable by hand.
    let rest = alias
        .trim_end_matches(['\n', '\r'])
        .strip_prefix(ALIAS_PREFIX)?
        .strip_prefix(':')?;
    let (nic_index, rest) = rest.split_once(':')?;
    let (instance_id, vm_id) = rest.split_once(':')?;
    let identity = InterfaceIdentity {
        instance_id: instance_id.to_string(),
        vm_id: vm_id.to_string(),
        nic_index: nic_index.parse().ok()?,
    };
    // The name is the proof. A record that does not reproduce it describes
    // some other interface, or nothing.
    (tap_name(&identity) == tap).then_some(identity)
}

/// Whether this name is one netd can have created. See [`TAP_PREFIX`].
pub fn is_managed_name(interface: &str) -> bool {
    let Some(digest) = interface.strip_prefix(TAP_PREFIX) else {
        return false;
    };
    digest.len() == TAP_DIGEST_CHARS
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Rejects an instance ID no interface could be recorded as belonging to.
///
/// At startup rather than at the first launch. The VMM derives one that is
/// always valid; an operator who configured their own learns here rather than
/// from the first VM that fails to get a NIC.
pub fn validate_instance_id(instance_id: &str) -> Result<()> {
    validate_identity(&InterfaceIdentity {
        instance_id: instance_id.to_string(),
        vm_id: "0".repeat(64),
        nic_index: MAX_NIC_INDEX,
    })
    .context("invalid cvm.instance_id")
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

    async fn remove_vm(self, request: VmRef) -> Result<RemoveVmResponse> {
        self.run(move |config| {
            let removed = sweep_vm_interfaces(
                &config.libvirt_uri,
                &request.instance_id,
                &request.vm_id,
                config.filter_policy().requires_binding(),
            )?;
            Ok(RemoveVmResponse { removed })
        })
        .await
    }

    async fn remove_interface_by_name(self, request: InterfaceName) -> Result<()> {
        self.run(move |config| {
            remove_interface_by_name(
                &config.libvirt_uri,
                &request.tap,
                config.filter_policy().requires_binding(),
            )
        })
        .await
    }

    async fn list_interfaces(self, request: ListInterfacesRequest) -> Result<InterfaceList> {
        self.run(move |config| {
            Ok(InterfaceList {
                interfaces: list_interfaces(&config.libvirt_uri, &request.instance_id),
            })
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
        set_alias(&tap, identity)?;
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
            info!(%tap, %parent, %mode, %device, %queues, workdir = %request.workdir, "prepared macvtap");
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
        // Before anything else it could fail at. An interface that exists
        // without a record is one nothing can attribute, and the window in
        // which that is true is the window a crash turns permanent.
        set_alias(&tap, identity)?;
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
    info!(
        %tap,
        bridge = %request.bridge,
        %filtered,
        %queues,
        workdir = %request.workdir,
        "prepared TAP"
    );
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
    /// The caller has already decided about the binding. Used by a pass over
    /// many interfaces, which asks libvirt once about all of them rather than
    /// once per interface.
    Skip,
}

/// Deletes every interface a VM could hold, by deriving each name rather than
/// consulting a record.
///
/// `validate_identity` caps the NIC index, so the whole space a VM can occupy
/// is enumerable: 256 names, each a `stat` that usually misses. Cleanup is
/// best-effort about unknown bindings on unfiltered nodes, which need not have
/// libvirtd at all. Filtered nodes must confirm their bindings were released.
///
/// A name with no interface is not skipped. An nwfilter binding outlives the
/// TAP it was bound to, so the one state teardown must not leave behind is
/// exactly the one a `/sys/class/net` check cannot see: the per-name Remove
/// this replaced deleted the binding unconditionally, and a sweep that reaches
/// less than the thing it replaced is not a sweep. Those names are decided
/// against a single listing, because the whole point of enumerating a bounded
/// space is that deciding one name stays cheap.
fn sweep_vm_interfaces(
    libvirt_uri: &str,
    instance_id: &str,
    vm_id: &str,
    requires_binding: bool,
) -> Result<u32> {
    let identity = InterfaceIdentity {
        instance_id: instance_id.to_string(),
        vm_id: vm_id.to_string(),
        nic_index: 0,
    };
    validate_identity(&identity)?;
    let listing = existing_bindings(libvirt_uri);
    // Not `listing.is_ok()`. A listing that could not be produced says
    // nothing about whether a *deletion* will work, and reading it as "libvirt
    // is down, skip the bindings" would mean a node whose listing breaks for
    // any reason silently stops cleaning up bindings at all -- which is worse
    // than the per-name asking this listing exists to avoid. The pass finds
    // out by trying, once. The exception is a listing that timed out: a
    // `libvirtd` that did not answer it will not answer a deletion either, and
    // waiting for that one too would outlast the caller's request.
    let mut libvirt = !listing.as_ref().is_err_and(timed_out);
    let bindings = listing.ok();
    let mut removed = 0;
    let mut first_error = (requires_binding && bindings.is_none())
        .then(|| anyhow::anyhow!("cannot confirm nwfilter cleanup: binding listing failed"));
    for nic_index in 0..=MAX_NIC_INDEX {
        let tap = tap_name(&InterfaceIdentity {
            nic_index,
            ..identity.clone()
        });
        let present = Path::new("/sys/class/net").join(&tap).exists();
        // A pass gets one answer about libvirt, not one per interface. Asking
        // again after it has failed is how a hung `libvirtd` turns a bounded
        // collection into an unbounded one.
        let known_binding = bindings.as_ref().is_some_and(|held| held.contains(&tap));
        if present {
            take_down(&tap);
        }
        let macvtap = present && is_macvtap(&tap);
        // A device netd did not create is refused below, before anything at
        // its name is touched, as a manual removal refuses it.
        let foreign = present && !macvtap && !is_tuntap(&tap);
        // A macvtap never carries a binding of its own, but a name that was a
        // filtered TAP before can still hold one that is listed.
        let wanted = !foreign && (known_binding || (present && !macvtap));
        if libvirt && wanted {
            if let Err(error) = delete_binding(libvirt_uri, &tap) {
                warn!(%tap, %error, "failed to remove an nwfilter binding");
                libvirt = false;
                // Unfiltered nodes do not require a running libvirtd. An
                // unknown, possible binding must not make a successful TAP
                // deletion fail there. Still retain failures for bindings we
                // actually found, including ones left by an older policy.
                if requires_binding || known_binding {
                    first_error.get_or_insert(error);
                }
            } else if !present {
                info!(%tap, %vm_id, "removed orphaned nwfilter binding");
            }
        }
        if !libvirt && known_binding {
            first_error
                .get_or_insert_with(|| anyhow::anyhow!("nwfilter binding {tap} was not released"));
        }
        if !present {
            continue;
        }
        // Keep going after a failure. Stopping at the first one would leave the
        // rest of a VM's interfaces behind over one that is stuck.
        match remove_interface(libvirt_uri, &tap, BindingCleanup::Skip) {
            Err(error) => {
                warn!(%tap, %error, "failed to remove interface");
                first_error.get_or_insert(error);
            }
            Ok(()) => {
                info!(%tap, %vm_id, "removed interface");
                removed += 1;
            }
        }
    }
    match first_error {
        Some(error) => Err(error).context("failed to remove every interface for this VM"),
        None => Ok(removed),
    }
}

/// Deletes one interface, and any binding at its name, for an operator.
///
/// `netd list` shows a binding whose interface is gone as its own row, and this
/// is how an operator removes it, so a binding that is known to exist, or that
/// is all the name could still hold, has to be confirmed gone before this
/// reports success. Only a binding that merely might sit next to a live
/// interface on a node that does not filter is best effort: `libvirtd` need
/// not be running there, and the interface still has to go. The same rules as
/// [`sweep_vm_interfaces`].
fn remove_interface_by_name(libvirt_uri: &str, tap: &str, requires_binding: bool) -> Result<()> {
    if !is_managed_name(tap) {
        bail!("{tap} is not a name netd could have created");
    }
    let present = Path::new("/sys/class/net").join(tap).exists();
    let macvtap = present && is_macvtap(tap);
    if present && !macvtap && !is_tuntap(tap) {
        bail!("refusing to delete {tap}: it is neither a tun/tap nor a macvtap device");
    }
    if present {
        take_down(tap);
    }
    let possible = |error: anyhow::Error| {
        warn!(%tap, "could not clear a possible nwfilter binding: {error:#}");
        None
    };
    let binding_error = match existing_bindings(libvirt_uri).map(|held| held.contains(tap)) {
        // Nothing listed at the name, and nothing there that could carry one.
        Ok(false) if !present || macvtap => None,
        Ok(known) => match delete_binding(libvirt_uri, tap) {
            Ok(()) => None,
            Err(error) if known || requires_binding => Some(error),
            Err(error) => possible(error),
        },
        // A macvtap carries no binding of its own, and there is no listing
        // saying an older one is left. A filtering node still needs that
        // confirmed, as a sweep does.
        Err(_) if macvtap && !requires_binding => None,
        Err(listing_error) => {
            // A `libvirtd` that did not answer the listing will not answer a
            // deletion either, and waiting for it would outlast the request.
            let attempt = if timed_out(&listing_error) {
                Err(listing_error.context("cannot confirm the binding is gone"))
            } else {
                delete_binding(libvirt_uri, tap).map_err(|error| {
                    error.context(format!(
                        "cannot confirm the binding is gone: {listing_error:#}"
                    ))
                })
            };
            match attempt {
                Ok(()) => None,
                Err(error) if present && !requires_binding => possible(error),
                Err(error) => Some(error),
            }
        }
    };
    // The interface goes even when its binding could not: a TAP left on the
    // bridge is worse than a binding with nothing to filter.
    remove_interface(libvirt_uri, tap, BindingCleanup::Skip)?;
    match binding_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Every resource netd owns, read off the host rather than out of a record.
///
/// Ownership is the reserved name plus the kernel's own answer about what kind
/// of device it is; attribution is the interface's alias, checked by
/// re-deriving the name from it. A listing never fails for want of libvirt: on
/// a node that does not filter, `libvirtd` need not be running, and an
/// interface inventory that refused to be produced without it would be
/// unavailable exactly where unfiltered TAPs live.
fn list_interfaces(libvirt_uri: &str, instance_id: &str) -> Vec<InterfaceRecord> {
    let bindings = existing_bindings(libvirt_uri).ok();
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let Ok(tap) = entry.file_name().into_string() else {
                continue;
            };
            if !is_managed_name(&tap) {
                continue;
            }
            let kind = if is_macvtap(&tap) {
                "macvtap"
            } else if is_tuntap(&tap) {
                "tap"
            } else {
                // The name is netd's to use, but this is not a device netd
                // creates. Listing it would invite a caller to delete it.
                continue;
            };
            let alias =
                std::fs::read_to_string(Path::new("/sys/class/net").join(&tap).join("ifalias"))
                    .unwrap_or_default();
            let owner = owner_of(&tap, &alias);
            seen.insert(tap.clone());
            records.push(InterfaceRecord {
                kind: kind.to_string(),
                nic_index: owner.as_ref().map(|identity| identity.nic_index),
                instance_id: owner.as_ref().map(|identity| identity.instance_id.clone()),
                vm_id: owner.map(|identity| identity.vm_id),
                tap,
            });
        }
    }
    // A binding outlives its interface, and an interface is the only thing that
    // carries a record, so an orphaned binding can never be attributed. It is
    // still netd's: nothing else creates a binding at one of these names.
    for name in bindings.into_iter().flatten() {
        if !seen.contains(&name) {
            records.push(InterfaceRecord {
                tap: name,
                kind: "binding".to_string(),
                instance_id: None,
                vm_id: None,
                nic_index: None,
            });
        }
    }
    if !instance_id.is_empty() {
        records.retain(|record| record.instance_id.as_deref() == Some(instance_id));
    }
    records.sort_by(|left, right| left.tap.cmp(&right.tap));
    records
}

fn remove_interface(libvirt_uri: &str, tap: &str, cleanup: BindingCleanup) -> Result<()> {
    let macvtap = is_macvtap(tap);
    if Path::new("/sys/class/net").join(tap).exists() {
        // The name is 48 bits of SHA-256, so a collision is not the worry. A
        // caller asserting an identity that happens to derive to some
        // pre-existing device is: netd runs as root and `ip link delete` does
        // not ask what it is deleting. netd creates exactly two kinds of
        // device, and the kernel publishes an attribute unique to each.
        if !macvtap && !is_tuntap(tap) {
            bail!("refusing to delete {tap}: it is neither a tun/tap nor a macvtap device");
        }
        let _ = ip(&["link", "set", "dev", tap, "down"]);
    }
    // A macvtap interface never carries a binding. Anything else might: this
    // name may have been a filtered bridge TAP before, and the binding
    // outlives the interface.
    if !macvtap {
        match cleanup {
            BindingCleanup::Skip => {}
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

/// Sets a device netd created down before anything else about it is torn down.
///
/// A stop only signals QEMU, so it may still be sending when its release runs.
/// Down first, so its traffic does not reach the bridge unfiltered for as long
/// as deleting the binding takes. Never touches a device netd did not create.
fn take_down(interface: &str) {
    if is_macvtap(interface) || is_tuntap(interface) {
        let _ = ip(&["link", "set", "dev", interface, "down"]);
    }
}

/// Records who an interface belongs to, on the interface. See
/// [`interface_alias`].
fn set_alias(tap: &str, identity: &InterfaceIdentity) -> Result<()> {
    let alias = interface_alias(identity);
    ip(&["link", "set", "dev", tap, "alias", &alias])
        .with_context(|| format!("failed to record ownership on {tap}"))
}

/// Whether this is a tun/tap device. `tun_flags` is published by the tun
/// driver and by nothing else, so its presence is the kernel's own answer --
/// as `macvtap/` is for the other kind of device netd creates.
fn is_tuntap(interface: &str) -> bool {
    Path::new("/sys/class/net")
        .join(interface)
        .join("tun_flags")
        .exists()
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
    if identity.nic_index > MAX_NIC_INDEX {
        bail!("NIC index is out of range");
    }
    // An identity that cannot be recorded on the interface is refused rather
    // than built unattributed. A host resource nothing can name the owner of
    // is the thing this whole path exists to stop producing, and the kernel's
    // alias is the only place with the interface's exact lifetime to put it.
    let alias = interface_alias(identity);
    if alias.len() > MAX_IFALIAS {
        bail!(
            "identity is too long to record on the interface: {} bytes of {MAX_IFALIAS}",
            alias.len()
        );
    }
    // The record puts the two free-form fields last, so only the first of them
    // has to be unambiguous.
    if identity.instance_id.contains(':') {
        bail!("instance ID must not contain ':'");
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
    virsh_output(uri, args, stdin).map(|_| ())
}

fn virsh_output(uri: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
    let mut full_args = vec!["--connect", uri];
    full_args.extend_from_slice(args);
    run_command_with_timeout(VIRSH_PATH, &full_args, stdin, COMMAND_TIMEOUT)
}

/// Every nwfilter binding libvirt holds at a name netd could have created.
///
/// One call, so that a sweep can decide 256 names against a set instead of
/// asking libvirt 256 times. `None` means libvirt could not be asked at all,
/// which on a node running unfiltered TAPs is the normal state -- `virsh` must
/// be installed for netd to start, but `libvirtd` need not be running.
///
/// The command has no machine-readable mode: it prints a two-line header and
/// then one binding per line, interface name first, and it accepts no options
/// at all -- `--name` is not one of them, and asking for it fails the whole
/// call. Narrowing to netd's own name space is what makes parsing a human
/// table safe: a header, a rule line, or a column that moves cannot produce a
/// `dt` name, and a binding at any other name is not netd's to reason about.
fn existing_bindings(uri: &str) -> Result<HashSet<String>> {
    // Shorter than a mutation's timeout. A sweep or a manual removal asks this
    // first, and the whole request has to fit in the VMM's own request
    // timeout, which a hung `libvirtd` would otherwise use up on its own.
    let output = run_command_with_timeout(
        VIRSH_PATH,
        &["--connect", uri, "nwfilter-binding-list"],
        None,
        LISTING_TIMEOUT,
    )
    .inspect_err(|error| debug!("could not list nwfilter bindings: {error:#}"))?;
    Ok(output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| is_managed_name(name))
        .map(str::to_string)
        .collect())
}

fn run_command(program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<()> {
    run_command_with_timeout(program, args, stdin, COMMAND_TIMEOUT).map(|_| ())
}

/// A helper that did not finish in time. Typed so a caller can tell a hung
/// daemon, which will not answer the next request either, from a refusal.
#[derive(Debug)]
struct CommandTimedOut {
    program: String,
    timeout: Duration,
}

impl std::fmt::Display for CommandTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} timed out after {:?}", self.program, self.timeout)
    }
}

impl std::error::Error for CommandTimedOut {}

fn timed_out(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<CommandTimedOut>().is_some())
}

fn run_command_with_timeout(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    command_timeout: Duration,
) -> Result<String> {
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
    // Drain both pipes while waiting. A child whose output fills a pipe
    // blocks until someone reads it, so waiting first and reading afterwards
    // turns any output larger than the pipe buffer -- a binding listing on a
    // busy host -- into a timeout.
    let stdout = drain(child.stdout.take().context("missing command stdout")?);
    let stderr = drain(child.stderr.take().context("missing command stderr")?);
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().context("missing command stdin")?;
        let input = input.to_vec();
        // On its own thread for the same reason: a child that writes before
        // it has read all of its input must not stall the write past the
        // timeout. Dropping the pipe afterwards is the child's EOF.
        std::thread::spawn(move || {
            let _ = pipe.write_all(&input);
        });
    }
    let Some(status) = child.wait_timeout(command_timeout)? else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CommandTimedOut {
            program: Path::new(program).display().to_string(),
            timeout: command_timeout,
        }
        .into());
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    if !status.success() {
        let error = String::from_utf8_lossy(&stderr);
        bail!("{} failed: {}", Path::new(program).display(), error.trim());
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Reads a pipe to its end on its own thread.
fn drain(mut pipe: impl io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = pipe.read_to_end(&mut buffer);
        buffer
    })
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

/// A netd that exists only to be talked to.
///
/// The VMM's side of the netd conversation -- what it refuses, what it does
/// when netd refuses -- needs no privileged daemon, only something that serves
/// the same RPC on a socket. This is that, scripted per method, recording what
/// it was asked so a test can assert on the conversation rather than on its
/// effects.
#[cfg(test)]
pub(crate) mod testing {
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use anyhow::{bail, Result};
    use ra_rpc::{CallContext, RpcCall};
    use serde_json::Value;
    use tokio::net::UnixListener;

    use super::{
        CheckInterfaceRequest, InterfaceIdentity, InterfaceList, InterfaceName,
        ListInterfacesRequest, NetdListener, NetdRpc, NetdServer, PrepareBridgeRequest,
        PrepareMacvtapRequest, PreparedInterface, RemoveVmResponse, VmRef,
    };

    #[derive(Clone)]
    pub(crate) struct FakeState {
        /// Methods answered with success; every other one is refused.
        handles: Arc<Vec<String>>,
        seen: Arc<Mutex<Vec<(String, Value)>>>,
    }

    pub(crate) struct FakeHandler(FakeState);

    impl RpcCall<FakeState> for FakeHandler {
        type PrpcService = NetdServer<Self>;

        fn construct(context: CallContext<'_, FakeState>) -> Result<Self> {
            Ok(Self(context.state.clone()))
        }
    }

    impl FakeHandler {
        fn record(&self, method: &str, request: impl serde::Serialize) -> Result<()> {
            self.0
                .seen
                .lock()
                .expect("poisoned")
                .push((method.to_string(), serde_json::to_value(request)?));
            if !self.0.handles.iter().any(|name| name == method) {
                bail!("fake netd refuses {method}");
            }
            Ok(())
        }
    }

    impl NetdRpc for FakeHandler {
        async fn prepare_bridge(self, request: PrepareBridgeRequest) -> Result<PreparedInterface> {
            let queues = request.queues.max(1);
            self.record("PrepareBridge", request)?;
            Ok(PreparedInterface {
                tap: "dtdeadbeef00".into(),
                device: String::new(),
                queues,
            })
        }

        async fn prepare_macvtap(
            self,
            request: PrepareMacvtapRequest,
        ) -> Result<PreparedInterface> {
            let queues = request.queues.max(1);
            self.record("PrepareMacvtap", request)?;
            Ok(PreparedInterface {
                tap: "dtdeadbeef00".into(),
                device: "/dev/tap1".into(),
                queues,
            })
        }

        async fn remove_interface(self, request: InterfaceIdentity) -> Result<()> {
            self.record("RemoveInterface", request)
        }

        async fn remove_vm(self, request: VmRef) -> Result<RemoveVmResponse> {
            self.record("RemoveVm", request)?;
            Ok(RemoveVmResponse { removed: 0 })
        }

        async fn remove_interface_by_name(self, request: InterfaceName) -> Result<()> {
            self.record("RemoveInterfaceByName", request)
        }

        async fn list_interfaces(self, request: ListInterfacesRequest) -> Result<InterfaceList> {
            self.record("ListInterfaces", request)?;
            Ok(InterfaceList::default())
        }

        async fn check_interface(self, request: CheckInterfaceRequest) -> Result<()> {
            self.record("CheckInterface", request)
        }
    }

    pub(crate) struct FakeNetd {
        _dir: Option<tempfile::TempDir>,
        socket: PathBuf,
        seen: Arc<Mutex<Vec<(String, Value)>>>,
    }

    impl FakeNetd {
        /// Serves on a fresh socket, answering `handles` and refusing the
        /// rest. The socket is bound before this returns, so a caller can
        /// connect at once.
        pub(crate) fn spawn(handles: &[&str]) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut netd = Self::spawn_at(&dir.path().join("netd.sock"), handles);
            netd._dir = Some(dir);
            netd
        }

        /// As [`FakeNetd::spawn`], on a socket path the caller chose -- for a
        /// netd that comes up after the VMM already started asking for it.
        pub(crate) fn spawn_at(socket: &Path, handles: &[&str]) -> Self {
            let socket = socket.to_path_buf();
            let listener = UnixListener::bind(&socket).expect("bind");
            let state = FakeState {
                handles: Arc::new(handles.iter().map(|name| name.to_string()).collect()),
                seen: Arc::new(Mutex::new(Vec::new())),
            };
            let seen = state.seen.clone();
            tokio::spawn(async move {
                let figment = rocket::Config::figment().merge(("log_level", "off"));
                let ignite = rocket::custom(figment)
                    .manage(state)
                    .mount("/prpc", ra_rpc::prpc_routes!(FakeState, FakeHandler))
                    .ignite()
                    .await
                    .expect("ignite fake netd");
                let _ = ignite.launch_on(NetdListener(listener)).await;
            });
            Self {
                _dir: None,
                socket,
                seen,
            }
        }

        pub(crate) fn socket(&self) -> &Path {
            &self.socket
        }

        /// Every request it was sent, in order.
        pub(crate) fn seen(&self) -> Vec<Value> {
            self.calls()
                .into_iter()
                .map(|(_, request)| request)
                .collect()
        }

        /// The method of every request it was sent, in order.
        pub(crate) fn methods(&self) -> Vec<String> {
            self.calls().into_iter().map(|(method, _)| method).collect()
        }

        fn calls(&self) -> Vec<(String, Value)> {
            self.seen.lock().expect("poisoned").clone()
        }
    }
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
            workdir: String::new(),
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
            workdir: String::new(),
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
            identity: Some(identity("i", "v", 0)),
            bridge: "br0".into(),
            mac: "02:00:00:00:00:01".into(),
            qemu_uid: 1000,
            filtered: true,
            queues: 1,
            workdir: String::new(),
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
        // Output larger than a pipe buffer is read, not mistaken for a hang.
        let large = run_command_with_timeout(
            "/bin/sh",
            &["-c", "head -c 1000000 /dev/zero | tr '\\0' x"],
            None,
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(large.len(), 1_000_000);
        // Input is still delivered, and its EOF still arrives.
        let echoed =
            run_command_with_timeout("/bin/cat", &[], Some(b"binding xml"), COMMAND_TIMEOUT)
                .unwrap();
        assert_eq!(echoed, "binding xml");
        // Recognised through whatever context a caller adds.
        assert!(timed_out(&error.context("while listing")));
        let refused = run_command_with_timeout("/bin/sh", &["-c", "exit 1"], None, COMMAND_TIMEOUT)
            .unwrap_err();
        assert!(!timed_out(&refused));
    }

    /// A whole-VM sweep names a VM and no NIC: reaching the indices the caller
    /// can no longer name is the point, so netd derives the whole space. That
    /// space is bounded by what an identity may say, which is what makes
    /// deriving it cheap enough to do on every launch.
    #[test]
    fn a_whole_vm_sweep_covers_a_bounded_space() {
        let value = serde_json::to_value(VmRef {
            instance_id: "instance".into(),
            vm_id: "vm".into(),
        })
        .unwrap();
        assert!(value.get("nic_index").is_none());

        let mut identity = identity("instance", "vm", MAX_NIC_INDEX);
        assert!(validate_identity(&identity).is_ok());
        identity.nic_index = MAX_NIC_INDEX + 1;
        assert!(validate_identity(&identity).is_err());
    }

    /// The record is a hint; the name is the proof. Everything that can go
    /// wrong with reading a string off an interface -- forged, truncated,
    /// ambiguous, absent -- has to land in the same bucket, and it has to be
    /// the bucket a collection treats conservatively.
    #[test]
    fn an_interface_says_whose_it_is_and_the_name_is_what_proves_it() {
        let nic = identity("path-abc", "vm-1", 3);
        let tap = tap_name(&nic);
        let alias = interface_alias(&nic);
        assert_eq!(alias, "dstack1:3:path-abc:vm-1");

        let owner = owner_of(&tap, &alias).expect("its own record checks out");
        assert_eq!(owner.instance_id, "path-abc");
        assert_eq!(owner.vm_id, "vm-1");
        assert_eq!(owner.nic_index, 3);

        // A record naming some other interface proves nothing about this one.
        // This is what makes the record unforgeable without making it
        // authoritative: anything that can reach the socket can write a
        // string, but only the true identity re-derives the name.
        let forged = interface_alias(&identity("path-abc", "someone-elses-vm", 3));
        assert!(owner_of(&tap, &forged).is_none());
        assert!(owner_of(&tap, "").is_none());
        assert!(owner_of(&tap, "dstack1:3:path-abc").is_none());
        assert!(owner_of(&tap, &alias[..alias.len() - 2]).is_none());
        // A format this build does not know is not this format.
        assert!(owner_of(&tap, &alias.replace("dstack1", "dstack2")).is_none());

        // The two free-form fields are last and only the first of them has to
        // be unambiguous, so a VM ID carrying the separator still reads back.
        let odd = identity("path-abc", "vm:with:colons", 0);
        assert_eq!(
            owner_of(&tap_name(&odd), &interface_alias(&odd)).map(|owner| owner.vm_id),
            Some("vm:with:colons".to_string())
        );
        // An instance ID carrying it is refused instead of mis-parsed.
        assert!(validate_identity(&identity("path:abc", "vm-1", 0)).is_err());
    }

    /// An identity that cannot be recorded would produce an interface nothing
    /// can attribute, which is the state this whole path exists to stop
    /// creating. Refusing it is the only answer that keeps the invariant.
    #[test]
    fn an_identity_too_long_to_record_is_refused() {
        let long = "v".repeat(128);
        assert!(validate_identity(&identity("instance", &long, 0)).is_ok());
        let identity_too_long = identity(&"i".repeat(128), &long, 255);
        assert!(interface_alias(&identity_too_long).len() > MAX_IFALIAS);
        let error = validate_identity(&identity_too_long)
            .unwrap_err()
            .to_string();
        assert!(error.contains("too long to record"), "{error}");
    }

    /// The name space netd claims. A collection deletes what matches, so what
    /// matches has to be exactly what netd can produce.
    #[test]
    fn the_managed_name_space_is_exactly_what_netd_produces() {
        assert!(is_managed_name(&tap_name(&identity("instance", "vm", 0))));
        assert!(is_managed_name("dt0123456789ab"));
        assert!(!is_managed_name("dt0123456789AB"), "digests are lower case");
        assert!(!is_managed_name("dt0123456789a"), "one short");
        assert!(!is_managed_name("dt0123456789abc"), "one long");
        assert!(!is_managed_name("dtzzzzzzzzzzzz"));
        assert!(!is_managed_name("virbr0"));
        assert!(!is_managed_name("eth0"));
        // The whole space fits in IFNAMSIZ, or the kernel would refuse the
        // names this reserves.
        assert!(tap_name(&identity("instance", "vm", 255)).len() < 16);
    }

    /// The command prints a table for a human and accepts no options to make it
    /// print anything else, so this parses one. Narrowing to netd's own name
    /// space is what makes that safe.
    #[test]
    fn the_binding_listing_reads_a_table_meant_for_a_person() {
        let output = "\
 Port Dev         Filter
---------------------------------
 dt1e053266e9f7   clean-traffic
 dt28b105b3031a   clean-traffic
 vnet3            some-other-filter
";
        let names: HashSet<String> = output
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|name| is_managed_name(name))
            .map(str::to_string)
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains("dt1e053266e9f7"));
        // The header, the rule, and a binding that is not netd's all fall out.
        assert!(!names.contains("Port"));
        assert!(!names.contains("vnet3"));
    }

    /// Everything else here reasons about strings. This puts the reasoning
    /// next to the kernel: that an alias survives on a device netd actually
    /// creates, that enumeration finds it, that the guards refuse what they
    /// are meant to, and that removal leaves nothing.
    ///
    /// Refuses to run in the host's network namespace, so it cannot touch a
    /// real node's interfaces even when it fails. Unsharing one from inside
    /// the test is not enough: `/sys/class/net` keeps showing the old
    /// namespace until sysfs is remounted, which is most of what `ip netns
    /// exec` does. So it asks to be put in one:
    ///
    /// ```text
    /// cargo test -p dstack-vmm --bins --no-run
    /// sudo ip netns add dstack-netd-test
    /// sudo ip netns exec dstack-netd-test \
    ///     target/debug/deps/dstack_vmm-<hash> --ignored --test-threads=1
    /// sudo ip netns del dstack-netd-test
    /// ```
    #[test]
    #[ignore = "needs root and its own network namespace; see the doc comment"]
    fn a_real_interface_carries_its_record_and_removal_leaves_nothing() {
        assert!(
            nix::unistd::Uid::effective().is_root(),
            "this test needs root"
        );
        let (mine, init) = (
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
        );
        assert_ne!(
            mine, init,
            "run this inside its own network namespace; it creates and deletes interfaces"
        );
        // Nothing in this namespace to talk to, which is also the state of a
        // node that does not filter: the listing has to work without libvirt.
        let uri = "qemu:///nonexistent-for-this-test";

        let nic = identity("test-instance", "vm-1", 2);
        let tap = tap_name(&nic);
        ip(&["tuntap", "add", "dev", &tap, "mode", "tap"]).unwrap();
        set_alias(&tap, &nic).unwrap();
        assert!(is_tuntap(&tap), "the kernel publishes tun_flags for a TAP");

        let records = list_interfaces(uri, "");
        let record = records
            .iter()
            .find(|record| record.tap == tap)
            .expect("an interface netd created is one netd can find");
        assert_eq!(record.instance_id.as_deref(), Some("test-instance"));
        assert_eq!(record.vm_id.as_deref(), Some("vm-1"));
        assert_eq!(record.nic_index, Some(2));
        assert_eq!(record.kind, "tap");
        // Narrowing by instance is what keeps one VMM's collection off
        // another's interfaces.
        assert_eq!(list_interfaces(uri, "test-instance").len(), 1);
        assert!(list_interfaces(uri, "someone-else").is_empty());

        // A device with one of netd's names that netd did not create. The name
        // is 48 bits of digest, so this is not about collisions -- it is that
        // `ip link delete` does not ask what it is deleting, and netd runs as
        // root.
        let impostor = tap_name(&identity("test-instance", "not-a-tap", 0));
        ip(&["link", "add", &impostor, "type", "dummy"]).unwrap();
        assert!(is_managed_name(&impostor));
        assert!(
            !list_interfaces(uri, "")
                .iter()
                .any(|record| record.tap == impostor),
            "a device netd did not create is not offered up for collection"
        );
        let refused = remove_interface(uri, &impostor, BindingCleanup::Skip).unwrap_err();
        assert!(refused.to_string().contains("refusing to delete"));

        // An interface whose record does not re-derive its own name proves
        // nothing, and lands in the same bucket as no record at all.
        ip(&[
            "link",
            "set",
            "dev",
            &tap,
            "alias",
            "dstack1:2:test-instance:some-other-vm",
        ])
        .unwrap();
        let records = list_interfaces(uri, "");
        let record = records.iter().find(|record| record.tap == tap).unwrap();
        assert!(record.instance_id.is_none(), "a forged record is no record");

        remove_interface(uri, &tap, BindingCleanup::Skip).unwrap();
        assert!(!Path::new("/sys/class/net").join(&tap).exists());
        assert!(!list_interfaces(uri, "")
            .iter()
            .any(|record| record.tap == tap));
        // Removing what is not there is not an error: a sweep derives names
        // and most of them miss.
        remove_interface(uri, &tap, BindingCleanup::Skip).unwrap();
    }

    /// Run with the same isolated-network-namespace setup as the test above.
    #[test]
    #[ignore = "needs root and its own network namespace"]
    fn sweeps_without_libvirt_follow_the_nodes_filter_policy() {
        assert!(nix::unistd::Uid::effective().is_root());
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "run this inside its own network namespace",
        );
        let uri = "qemu:///nonexistent-for-this-test";
        for requires_binding in [false, true] {
            let nic = identity("sweep-test", "vm-1", 0);
            let tap = tap_name(&nic);
            ip(&["tuntap", "add", "dev", &tap, "mode", "tap"]).unwrap();
            let mut config = NetdConfig {
                libvirt_uri: uri.into(),
                ..Default::default()
            };
            config.network_filter = Some(NetworkFilterConfig {
                mode: if requires_binding {
                    crate::config::NetworkFilterMode::Libvirt
                } else {
                    crate::config::NetworkFilterMode::None
                },
                ..Default::default()
            });
            let sweep = || {
                sweep_vm_interfaces(
                    &config.libvirt_uri,
                    &nic.instance_id,
                    &nic.vm_id,
                    config.filter_policy().requires_binding(),
                )
            };
            let result = sweep();
            // Even a binding failure must not leave the TAP on the bridge.
            assert!(!Path::new("/sys/class/net").join(&tap).exists());
            if requires_binding {
                assert!(result.is_err());
                // A retry cannot claim success just because the TAP is gone:
                // its binding may still exist in the unreachable libvirt.
                assert!(sweep().is_err());
            } else {
                assert_eq!(result.unwrap(), 1);
                assert_eq!(sweep().unwrap(), 0);
            }
        }
    }

    /// Run with the same isolated-network-namespace setup as the tests above.
    /// A manual removal reports success only once nothing at the name is left
    /// that the node's policy needs confirmed.
    #[test]
    #[ignore = "needs root and its own network namespace"]
    fn a_manual_removal_does_not_claim_a_binding_it_could_not_confirm() {
        assert!(nix::unistd::Uid::effective().is_root());
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "run this inside its own network namespace",
        );
        let uri = "qemu:///nonexistent-for-this-test";
        let tap = tap_name(&identity("manual-test", "vm-1", 0));

        // Nothing but a possible binding at the name, and no libvirt to ask.
        let error = remove_interface_by_name(uri, &tap, false).unwrap_err();
        assert!(format!("{error:#}").contains("cannot confirm"), "{error:#}");

        for requires_binding in [false, true] {
            ip(&["tuntap", "add", "dev", &tap, "mode", "tap"]).unwrap();
            let result = remove_interface_by_name(uri, &tap, requires_binding);
            assert!(
                !Path::new("/sys/class/net").join(&tap).exists(),
                "the interface goes whatever happened to its binding"
            );
            assert_eq!(result.is_err(), requires_binding, "{result:?}");
        }

        let impostor = tap_name(&identity("manual-test", "not-a-tap", 0));
        ip(&["link", "add", &impostor, "type", "dummy"]).unwrap();
        let refused = remove_interface_by_name(uri, &impostor, false).unwrap_err();
        assert!(refused.to_string().contains("refusing to delete"));
        ip(&["link", "delete", "dev", &impostor]).unwrap();
        assert!(remove_interface_by_name(uri, "eth0", false).is_err());
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
