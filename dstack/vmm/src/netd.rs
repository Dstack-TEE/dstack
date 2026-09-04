// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Small privileged broker for TAP creation and libvirt nwfilter bindings.

use std::{
    collections::HashSet,
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
/// How long a capability probe waits. See [`probe`].
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const IP_PATH: &str = "/usr/sbin/ip";
const VIRSH_PATH: &str = "/usr/bin/virsh";
const LOCK_PATH: &str = "/run/lock/dstack-netd.lock";
/// Upper bound on TAP queue pairs netd will create. Mirrors the VMM's own cap
/// so a malformed request cannot ask the kernel for an unbounded device.
const MAX_QUEUES: u32 = 64;
/// Highest NIC index an identity may name. Also the width of the space a
/// whole-VM sweep has to enumerate, since it derives names instead of reading a
/// record.
const MAX_NIC_INDEX: usize = 255;
/// Every operation this netd accepts, answered to `hello`.
const OPERATIONS: &[&str] = &[
    "hello",
    "prepare_bridge",
    "prepare_macvtap",
    "remove",
    "remove_all",
    "list",
    "remove_interface",
    "check",
];
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
/// How long a sweep or collection keeps starting work on new interfaces.
///
/// A bound on when the pass stops, not on how long one interface takes: an
/// interface it has already begun is still bounded only by `COMMAND_TIMEOUT`
/// per helper invocation, so a pass that passes this check at 19.9s can run on
/// for as long as the `ip` and `virsh` calls it has started take to time out.
///
/// What it protects is the caller's patience against the operation lock. Every
/// other prepare and remove on the host waits behind a pass, and the caller
/// that asked for this one gave up at thirty seconds; work done after that is
/// work nobody is waiting for, done while everybody waits. Partial progress
/// reported honestly beats total progress reported to nobody.
const COLLECTION_DEADLINE: Duration = Duration::from_secs(20);

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
    /// Untrusted and never read for a decision: any process that can reach the
    /// socket can assert anything here. It is carried so an operator reading
    /// netd's log can get from an opaque TAP name back to the VM that asked for
    /// it without going through the VMM.
    #[serde(default)]
    pub workdir: String,
    /// Host ports this VM wants reachable at its guest.
    ///
    /// Empty asks for nothing, which is also what a caller predating the field
    /// sends. Whether a netd forwards them is its own business; this states the
    /// requirement rather than assuming it is met, and the response says what
    /// was actually done.
    ///
    /// Owned by the interface. Whatever a netd establishes to satisfy this is
    /// released when the interface is -- by `remove`, by `remove_all`, or by a
    /// collection -- and there is deliberately no operation that releases it
    /// separately. A host port outliving the interface it was forwarding to is
    /// a leak nothing would ever collect: the interface is the only thing that
    /// carries an ownership record, so a reservation that survived it could
    /// never be attributed to a VM again. A prepare for an identity that
    /// already has an interface replaces both together.
    #[serde(default)]
    pub ingress: Vec<IngressRequest>,
}

/// One host port a VM wants reachable at its guest.
///
/// Every field is named by the caller, which is what `bridge`, `mac` and
/// `queues` already get and the opposite of `filtered`. The difference is
/// whether netd can check what it is handed: an nwfilter name cannot be checked
/// for whether it filters anything, while a host port is a closed space a node
/// policy can be stated over. Naming is not deciding -- which ports may be
/// handed out stays netd's own configuration, exactly as `allowed_bridges`
/// governs the bridge a caller names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressRequest {
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    /// Host address to accept on. Empty leaves the choice to netd.
    ///
    /// Not decoration: an admin port bound to loopback and a published one
    /// differ only here.
    #[serde(default)]
    pub host_address: String,
    /// Host port, as the deployment named it. There is no "pick one for me":
    /// the caller reports this number back through `GetInfo` and a client
    /// connects to it, so a netd-chosen port would have to travel back through
    /// both before it meant anything.
    pub host_port: u16,
    pub guest_port: u16,
}

/// One forwarding rule a netd established, echoed so the caller can report what
/// the VM actually got rather than what it asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressBinding {
    pub protocol: String,
    pub host_address: String,
    pub host_port: u16,
    pub guest_port: u16,
}

/// One host resource netd holds.
///
/// `instance_id` and `vm_id` are absent when the interface carries no record
/// that checks out: built by a netd too old to write one, by a third-party
/// netd, or by this one in the instant between creating the interface and
/// recording it. Absent is not "nobody's" -- it is "not known to be anybody's",
/// which is a materially different thing to a collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceRecord {
    pub tap: String,
    /// `"tap"`, `"macvtap"`, or `"binding"` for an nwfilter binding whose
    /// interface is already gone. A binding outlives the interface it was
    /// bound to, so a collection that only looked at interfaces would leave
    /// the one piece of state that survives them.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_index: Option<usize>,
    /// Whether libvirt holds an nwfilter binding at this name.
    #[serde(default)]
    pub bound: bool,
}

/// What a netd can do, asked rather than inferred from a failure.
///
/// `queues` and `ingress` report a *missing feature* by leaving a response
/// field out, which works because both ride on an operation every netd has. An
/// operation a netd does not have cannot answer that way: it fails, and a
/// failure is indistinguishable from the operation failing for a real reason.
/// A caller left to guess from the message either turns a missing feature into
/// an outage or turns a real failure into silence -- and teardown, where the
/// consequence of guessing wrong is a leaked host interface, is exactly where
/// neither is acceptable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Implementation and version, for the operator's log. Never parsed:
    /// `operations` is what decisions are made from.
    #[serde(default)]
    pub version: String,
    /// Every operation this netd accepts.
    #[serde(default)]
    pub operations: Vec<String>,
    /// Whether it forwards host ports at all. A prepare's `ingress` field still
    /// says what one interface actually got; this says whether asking is
    /// meaningful, which is what deployment has to know before any prepare
    /// exists to read.
    #[serde(default)]
    pub ingress: bool,
    /// Whether it records ownership on the interface itself. A whole-host
    /// collection cannot tell one VMM instance's interfaces from another's
    /// without it, so a netd that says no is never asked to act on the
    /// *absence* of a record: "no record" would describe every interface on
    /// the host, including another instance's running VMs.
    #[serde(default)]
    pub attribution: bool,
}

impl Capabilities {
    pub fn supports(&self, operation: &str) -> bool {
        self.operations.iter().any(|name| name == operation)
    }
}

impl IngressBinding {
    /// Whether this binding answers a request for one host port.
    ///
    /// The address is part of the answer, not decoration: an admin port bound
    /// to loopback and a published one differ only there, so a netd that
    /// narrowed `0.0.0.0` to `127.0.0.1` has not met the request, and
    /// reporting it as met would report a port as reachable from the network
    /// when it is not. An address netd did not state at all is not a narrowing;
    /// it is a netd that echoes less than it was told.
    pub fn answers(
        &self,
        protocol: &str,
        host_address: &str,
        host_port: u16,
        guest_port: u16,
    ) -> bool {
        self.protocol == protocol
            && self.host_port == host_port
            && self.guest_port == guest_port
            && (self.host_address.is_empty() || self.host_address == host_address)
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    /// Ask what this netd can do, before asking it to do anything.
    ///
    /// Cheap by construction: answered without taking the operation lock, so a
    /// caller learns what netd can do without first waiting for what it is
    /// doing. It doubles as the liveness probe -- a netd that answers is up,
    /// and one that predates this answers an error, which is still an answer.
    Hello,
    PrepareBridge(PrepareBridgeRequest),
    PrepareMacvtap(PrepareMacvtapRequest),
    ///
    /// Releases everything the interface owns, including any host ports a
    /// forwarding netd published for it. See [`PrepareBridgeRequest::ingress`].
    Remove {
        #[serde(flatten)]
        identity: InterfaceIdentity,
        /// Whether this interface was created with an nwfilter binding.
        ///
        /// Advisory, and no longer read: removal detects macvtap itself, and
        /// clears a binding best-effort whatever this says. The strict rule it
        /// used to select exists for prepare, where a binding left at the name
        /// blocks the one about to be created; at removal it only left the
        /// interface up on the bridge. Still sent, and still required on
        /// decode, so a netd that predates that reasoning keeps working.
        filtered: bool,
    },
    /// Delete every interface netd holds for one VM.
    ///
    /// Teardown by identity can only reach the NIC indices its caller still has
    /// a record of, and that record is written after the interface exists: a
    /// VMM killed in between leaves a TAP nothing on disk points at. A manifest
    /// that lost a NIC leaves the same thing behind. Both are found here
    /// without a record, because every name netd can produce for a VM is
    /// derivable from its identity.
    ///
    /// Releases everything those interfaces own, host ports included. See
    /// [`PrepareBridgeRequest::ingress`].
    RemoveAll {
        instance_id: String,
        vm_id: String,
    },
    /// Everything netd holds, so that an operator -- and a reconciliation --
    /// can see the host's interfaces without being told what to look for.
    ///
    /// Deriving a name answers "where is this VM's interface". It cannot
    /// answer "whose is this interface", which is the question a leak is made
    /// of: a VM whose directory was deleted, a VMM instance that was
    /// decommissioned, an interface built by a netd that has since been
    /// upgraded. Enumeration answers it.
    List {
        /// Only interfaces recorded as this instance's. Empty lists every one
        /// netd owns, whatever it is recorded as and whether or not it is.
        #[serde(default)]
        instance_id: String,
    },
    /// Delete one interface by name.
    ///
    /// For what nothing else can reach: an interface built before netd recorded
    /// ownership, or by another netd, whose VM is gone. Nothing can attribute
    /// it, so nothing can decide about it -- but an operator looking at
    /// `list` can, and this is how they say so. Guarded the same way every
    /// other removal is: the name must be one netd could have created, and the
    /// device must be one netd creates.
    RemoveInterface {
        tap: String,
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
    /// Forwarding rules netd established. Absent from a netd that does not
    /// forward host ports, which is how the caller tells "nothing was asked
    /// for" apart from "this request was ignored" -- the same reading `queues`
    /// gets above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress: Option<Vec<IngressBinding>>,
    /// How many interfaces a whole-VM sweep deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    removed: Option<usize>,
    /// What this netd can do. Absent from one that predates `hello`, which is
    /// the same reading `queues` and `ingress` get.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capabilities: Option<Capabilities>,
    /// Whether the pass stopped on its deadline with work left. See
    /// [`COLLECTION_DEADLINE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    incomplete: Option<bool>,
    /// For a listing, everything netd holds; for a collection, what it took,
    /// or would take on a dry run. Absent, rather than empty, from a netd that
    /// cannot enumerate: "I hold nothing" and "I cannot say" are answers a
    /// collection must not confuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interfaces: Option<Vec<InterfaceRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// What one request produced.
///
/// An enum rather than a struct of options, because the shapes do not overlap:
/// a prepare names an interface, a sweep counts them, a probe names neither.
/// One flat [`Response`] still carries all of them on the wire, so a netd that
/// grows an operation stays readable to a caller that does not know it.
enum Outcome {
    /// One interface, named because the caller hands that name to QEMU.
    Interface {
        tap: String,
        device: Option<String>,
        queues: Option<u32>,
        ingress: Option<Vec<IngressBinding>>,
    },
    /// A sweep names no single interface, so it reports how many it deleted.
    Swept {
        removed: usize,
        incomplete: bool,
    },
    Hello(Capabilities),
    Listed(Vec<InterfaceRecord>),
}

impl Outcome {
    fn tap(tap: String) -> Self {
        Self::Interface {
            tap,
            device: None,
            queues: None,
            ingress: None,
        }
    }

    fn into_response(self) -> Response {
        let mut response = Response {
            ok: true,
            tap: None,
            device: None,
            queues: None,
            ingress: None,
            removed: None,
            capabilities: None,
            incomplete: None,
            interfaces: None,
            error: None,
        };
        match self {
            Self::Interface {
                tap,
                device,
                queues,
                ingress,
            } => {
                response.tap = Some(tap);
                response.device = device;
                response.queues = queues;
                response.ingress = ingress;
            }
            Self::Swept {
                removed,
                incomplete,
            } => {
                response.removed = Some(removed);
                response.incomplete = Some(incomplete);
            }
            Self::Hello(capabilities) => response.capabilities = Some(capabilities),
            Self::Listed(interfaces) => response.interfaces = Some(interfaces),
        }
        response
    }
}

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
    let rest = alias.trim().strip_prefix(ALIAS_PREFIX)?.strip_prefix(':')?;
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

pub struct PreparedInterface {
    pub device: Option<String>,
    pub queues: Option<u32>,
    /// The forwarding rules netd established, if it forwards host ports at all.
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
///
/// `downcast_ref` rather than a walk over `chain()`: a marker attached with
/// `context` is not a link in the source chain, it is the context *of* a link,
/// and `chain()` yields the wrapper rather than the marker inside it. Asking
/// the chain therefore always answered no -- which made every "an unreachable
/// netd is not a failure" branch in this crate unreachable itself.
pub fn is_unreachable(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Unreachable>().is_some()
}

pub async fn request(socket: &Path, request: &Request) -> Result<PreparedInterface> {
    let response = exchange(socket, request).await?;
    if response.tap.as_deref().unwrap_or_default().is_empty() {
        bail!("netd response omitted TAP name");
    }
    Ok(PreparedInterface {
        device: response.device,
        queues: response.queues,
        ingress: response.ingress,
    })
}

/// Deletes every interface netd holds for one VM, returning how many there
/// were. See [`Request::RemoveAll`].
///
/// A netd that answers without a count did not sweep. Reading that as zero
/// would report a netd that cannot do this as a VM that had nothing to remove,
/// which is the conflation [`Capabilities`] exists to end -- so it is an error
/// here, and the caller falls back to removing what it has a record of.
pub async fn remove_all(socket: &Path, instance_id: &str, vm_id: &str) -> Result<Sweep> {
    let request = Request::RemoveAll {
        instance_id: instance_id.to_string(),
        vm_id: vm_id.to_string(),
    };
    let response = exchange(socket, &request).await?;
    Ok(Sweep {
        removed: response
            .removed
            .context("netd answered a sweep without saying what it removed")?,
        // Absent from a netd that cannot stop early, which is the same as one
        // that did not.
        incomplete: response.incomplete.unwrap_or_default(),
    })
}

/// What one whole-VM sweep did.
#[derive(Debug, Clone, Copy)]
pub struct Sweep {
    pub removed: usize,
    /// Whether it stopped on its deadline with names left to check. Reported
    /// rather than dropped: a sweep that ran out of time and one that finished
    /// having removed the same count are different states of the host, and
    /// only one of them needs looking at.
    pub incomplete: bool,
}

/// Deletes one interface by name. See [`Request::RemoveInterface`].
pub async fn remove_interface_named(socket: &Path, tap: &str) -> Result<()> {
    let request = Request::RemoveInterface {
        tap: tap.to_string(),
    };
    exchange(socket, &request).await.map(|_| ())
}

/// Everything netd holds, optionally narrowed to one VMM instance. See
/// [`Request::List`].
pub async fn list(socket: &Path, instance_id: &str) -> Result<Vec<InterfaceRecord>> {
    let request = Request::List {
        instance_id: instance_id.to_string(),
    };
    exchange(socket, &request)
        .await?
        .interfaces
        .context("netd answered a listing without one")
}

/// This node's netd, as far as it can be asked.
#[derive(Debug, Clone)]
pub enum Reachability {
    /// Nothing is listening. Not a failure: most nodes run no netd, and a VM
    /// that needs none never notices.
    Unreachable,
    /// Reached, but it predates `hello`. Everything in [`OPERATIONS`] before
    /// `hello` was added is assumed; nothing after it is.
    Legacy,
    Capable(Capabilities),
}

impl Reachability {
    /// Whether netd answered at all.
    pub fn is_reachable(&self) -> bool {
        !matches!(self, Self::Unreachable)
    }

    pub fn supports(&self, operation: &str) -> bool {
        match self {
            Self::Unreachable | Self::Legacy => false,
            Self::Capable(capabilities) => capabilities.supports(operation),
        }
    }

    /// Whether it records which VM an interface belongs to. Unknown counts as
    /// no, for the same reason `forwards_ingress` does.
    pub fn records_ownership(&self) -> bool {
        matches!(self, Self::Capable(capabilities) if capabilities.attribution)
    }

    /// Whether asking this netd to forward host ports is meaningful. Unknown
    /// counts as no: a caller that assumed yes would report ports as published
    /// on the strength of never having asked.
    pub fn forwards_ingress(&self) -> bool {
        matches!(self, Self::Capable(capabilities) if capabilities.ingress)
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Unreachable => "unreachable".to_string(),
            Self::Legacy => "reachable, predates capability reporting".to_string(),
            Self::Capable(capabilities) => {
                format!(
                    "{} [{}]",
                    capabilities.version,
                    capabilities.operations.join(" ")
                )
            }
        }
    }
}

/// Asks what this node's netd can do.
///
/// Never fails: not being there, and being there but too old to say, are both
/// answers a caller has to act on rather than propagate. Both are also
/// distinguishable here and nowhere else -- an error from any other operation
/// cannot tell "netd refused this" from "netd does not have this".
pub async fn probe(socket: &Path) -> Reachability {
    // Bounded well below the request timeout. Every teardown asks, and a netd
    // that accepts a connection and then stops answering must not turn each of
    // them into a thirty-second stall; not answering promptly is, for the
    // caller's purposes, the same as not being there.
    let answer = match timeout(PROBE_TIMEOUT, exchange(socket, &Request::Hello)).await {
        Ok(answer) => answer,
        Err(_) => {
            warn!("netd accepted a connection but did not answer hello in time");
            return Reachability::Unreachable;
        }
    };
    match answer {
        Ok(response) => match response.capabilities {
            Some(capabilities) => Reachability::Capable(capabilities),
            // It answered `hello` with nothing to say, which is not a shape
            // this netd produces. Treat it as the older protocol rather than
            // trusting an empty capability set.
            None => Reachability::Legacy,
        },
        // It answered, so it is up; it just does not know the question.
        Err(error) if !is_unreachable(&error) => {
            debug!("netd does not answer hello: {error:#}");
            Reachability::Legacy
        }
        Err(_) => Reachability::Unreachable,
    }
}

async fn exchange(socket: &Path, request: &Request) -> Result<Response> {
    let operation = match request {
        Request::Hello => "hello",
        Request::PrepareBridge(_) => "prepare_bridge",
        Request::PrepareMacvtap(_) => "prepare_macvtap",
        Request::Remove { .. } => "remove",
        Request::RemoveAll { .. } => "remove_all",
        Request::List { .. } => "list",
        Request::RemoveInterface { .. } => "remove_interface",
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
    let config = std::sync::Arc::new(config);
    loop {
        let (mut stream, _) = listener.accept().await?;
        // One task per connection, so a request that takes minutes does not
        // stop the next one from being *accepted*.
        //
        // Serialization still holds where it matters, and holds where it is
        // actually stated: `handle_request` takes the operation lock, which is
        // an flock and blocks between two open descriptions in one process
        // just as it does between processes. What a single-connection accept
        // loop added on top of that was head-of-line blocking -- a caller
        // asking netd a question it answers in microseconds waited for whatever
        // netd happened to be doing, and gave up believing netd was not there.
        // A collection can run for twenty seconds and a `virsh` for thirty, so
        // this was not a corner: it made a busy netd indistinguishable from an
        // absent one, and teardown skips an absent netd.
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(&config, &mut stream).await {
                warn!(%error, "netd connection failed");
            }
        });
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

/// Serves one connection.
///
/// The timeouts bound the socket reads and writes and nothing else. They used
/// to wrap the whole exchange, which read as a bound on the request but was
/// not one: `handle_request` is synchronous and shells out, so the timeout
/// could not cancel it -- it only threw away the answer to work that went on
/// running. A caller has its own deadline and will have gone by then; what it
/// cost was netd's own log, which reported "timed out" for a request it in
/// fact completed. Helper execution is bounded where it can be, by
/// COMMAND_TIMEOUT per invocation.
async fn serve_connection(
    config: &std::sync::Arc<NetdConfig>,
    stream: &mut UnixStream,
) -> Result<()> {
    // Access is authorized by the Unix socket's owner, group, and mode. Any
    // process that can connect is trusted with the complete netd protocol.
    let request = timeout(CONNECTION_TIMEOUT, read_request(stream))
        .await
        .context("timed out reading a netd request")?;
    let outcome = match request {
        // A peer that connects and closes without sending is the VMM's
        // reachability check: netd that died leaves its socket behind, so the
        // VMM connects to tell the two apart. Answering that with a parse error
        // and a warning would fill the log with reports of it working.
        Ok(None) => {
            debug!("netd liveness probe");
            return Ok(());
        }
        Ok(Some(request)) => {
            // `handle_request` shells out to `ip` and `virsh` and waits on the
            // operation lock, so it can block for as long as those take. On a
            // runtime worker that would stall every other connection's reads
            // and writes, which is the head-of-line blocking this daemon just
            // stopped having.
            let config = config.clone();
            match tokio::task::spawn_blocking(move || handle_request(&config, request)).await {
                Ok(outcome) => outcome,
                Err(error) => Err(anyhow::anyhow!("netd worker failed: {error}")),
            }
        }
        // A request that arrived but could not be understood still gets an
        // answer. A VMM newer than this netd sends operations it does not
        // know, and "unknown variant `prepare_foo`" is what tells the operator
        // to upgrade; a closed connection tells them nothing.
        Err(error) => Err(error),
    };
    let response = match outcome {
        Ok(outcome) => outcome.into_response(),
        Err(error) => {
            warn!(%error, "netd request failed");
            Response {
                ok: false,
                tap: None,
                device: None,
                queues: None,
                ingress: None,
                removed: None,
                capabilities: None,
                incomplete: None,
                interfaces: None,
                error: Some(format!("{error:#}")),
            }
        }
    };
    let encoded = serde_json::to_vec(&response)?;
    timeout(CONNECTION_TIMEOUT, async {
        stream.write_all(&encoded).await?;
        stream.shutdown().await
    })
    .await
    .context("timed out answering a netd request")??;
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

/// What this build of netd can do. See [`Capabilities`].
fn capabilities() -> Capabilities {
    Capabilities {
        version: format!("dstack-netd {}", env!("CARGO_PKG_VERSION")),
        operations: OPERATIONS.iter().map(|name| name.to_string()).collect(),
        // This netd builds interfaces; it is not the host's forwarder. The
        // response field says so per prepare; this says so before one.
        ingress: false,
        attribution: true,
    }
}

fn handle_request(config: &NetdConfig, request: Request) -> Result<Outcome> {
    // Answered before the lock. A caller asks this to find out whether netd
    // can do the thing it is about to ask for, and making it wait behind a
    // running collection would put a whole-host sweep in front of every
    // launch's first question.
    if matches!(request, Request::Hello) {
        return Ok(Outcome::Hello(capabilities()));
    }
    let libvirt_uri = config.libvirt_uri.as_str();
    let _lock = OperationLock::acquire()?;
    match request {
        // Handled above, before the lock.
        Request::Hello => Ok(Outcome::Hello(capabilities())),
        Request::PrepareBridge(request) => {
            prepare_bridge(libvirt_uri, &request, config.filter_policy())
        }
        Request::PrepareMacvtap(request) => {
            prepare_macvtap(libvirt_uri, &request, config.filter_policy())
        }
        Request::List { instance_id } => {
            Ok(Outcome::Listed(list_interfaces(libvirt_uri, &instance_id)))
        }
        Request::RemoveAll { instance_id, vm_id } => {
            let (removed, incomplete) = sweep_vm_interfaces(libvirt_uri, &instance_id, &vm_id)?;
            Ok(Outcome::Swept {
                removed,
                incomplete,
            })
        }
        Request::RemoveInterface { tap } => {
            if !is_managed_name(&tap) {
                bail!("{tap} is not a name netd could have created");
            }
            remove_interface(libvirt_uri, &tap, BindingCleanup::BestEffort)?;
            Ok(Outcome::tap(tap))
        }
        Request::Remove {
            identity,
            filtered: _,
        } => {
            validate_identity(&identity)?;
            let tap = tap_name(&identity);
            // Best effort, whatever the caller says was built. The strict rule
            // exists for prepare, where a binding left at the name would block
            // the one about to be created; at removal nothing is about to take
            // the name, and failing here leaves the interface itself up on the
            // bridge rather than just a binding libvirt will hand back on its
            // next listing. It also makes this agree with the whole-VM sweep,
            // which has always been best effort.
            remove_interface(libvirt_uri, &tap, BindingCleanup::BestEffort)?;
            Ok(Outcome::tap(tap))
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
            Ok(Outcome::tap(tap))
        }
    }
}

fn prepare_macvtap(
    libvirt_uri: &str,
    request: &PrepareMacvtapRequest,
    filter: &NetworkFilterConfig,
) -> Result<Outcome> {
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
            info!(%tap, %parent, %mode, %device, %queues, "prepared macvtap");
            Ok(Outcome::Interface {
                tap,
                device: Some(device),
                queues: Some(queues),
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
) -> Result<Outcome> {
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
        // Before anything else it could fail at. An interface that exists
        // without a record is one nothing can attribute, and the window in
        // which that is true is the window a crash turns permanent.
        set_alias(&tap, &request.identity)?;
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
    Ok(Outcome::Interface {
        tap,
        device: None,
        queues: Some(queues),
        // This netd builds interfaces; it is not the host's forwarder. Saying
        // nothing here is what tells the caller that, so ports it asked for are
        // reported as unmet rather than assumed done.
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
    /// The caller has already decided about the binding. Used by a pass over
    /// many interfaces, which asks libvirt once about all of them rather than
    /// once per interface.
    Skip,
}

/// Removes one interface during a pass over many.
///
/// A pass gets one answer about libvirt, not one per interface. Asking again
/// after it has failed is how a hung `libvirtd` turns a bounded collection into
/// an unbounded one: the deadline is reached having deleted nothing, while
/// every other VM on the host waits behind the operation lock.
fn remove_interface_in_pass(uri: &str, tap: &str, libvirt: &mut bool) -> Result<()> {
    if *libvirt && !is_macvtap(tap) {
        if let Err(error) = delete_binding(uri, tap) {
            warn!(%tap, "could not clear a possible nwfilter binding: {error:#}");
            *libvirt = false;
        }
    }
    remove_interface(uri, tap, BindingCleanup::Skip)
}

/// Deletes every interface a VM could hold, by deriving each name rather than
/// consulting a record.
///
/// `validate_identity` caps the NIC index, so the whole space a VM can occupy
/// is enumerable: 256 names, each a `stat` that usually misses. Cleanup is
/// best-effort about bindings -- nothing is about to take these names, and a
/// node running unfiltered TAPs need not have libvirtd at all.
///
/// A name with no interface is not skipped. An nwfilter binding outlives the
/// TAP it was bound to, so the one state teardown must not leave behind is
/// exactly the one a `/sys/class/net` check cannot see: the per-name Remove
/// this replaced deleted the binding unconditionally, and a sweep that reaches
/// less than the thing it replaced is not a sweep. Those names are decided
/// against a single listing, because the whole point of enumerating a bounded
/// space is that deciding one name stays cheap.
fn sweep_vm_interfaces(libvirt_uri: &str, instance_id: &str, vm_id: &str) -> Result<(usize, bool)> {
    let identity = InterfaceIdentity {
        instance_id: instance_id.to_string(),
        vm_id: vm_id.to_string(),
        nic_index: 0,
    };
    validate_identity(&identity)?;
    let bindings = existing_bindings(libvirt_uri);
    // Not `bindings.is_some()`. A listing that could not be produced says
    // nothing about whether a *deletion* will work, and reading it as "libvirt
    // is down, skip the bindings" would mean a node whose listing breaks for
    // any reason silently stops cleaning up bindings at all -- which is worse
    // than the per-name asking this listing exists to avoid. The pass finds
    // out by trying, once.
    let mut libvirt = true;
    let mut removed = 0;
    let mut incomplete = false;
    let mut first_error = None;
    let deadline = std::time::Instant::now() + COLLECTION_DEADLINE;
    for nic_index in 0..=MAX_NIC_INDEX {
        if std::time::Instant::now() >= deadline {
            warn!(%vm_id, nic_index, "sweep stopped on its deadline");
            incomplete = true;
            break;
        }
        let tap = tap_name(&InterfaceIdentity {
            nic_index,
            ..identity.clone()
        });
        let present = Path::new("/sys/class/net").join(&tap).exists();
        if !present {
            if libvirt
                && bindings
                    .as_ref()
                    .is_some_and(|bindings| bindings.contains(&tap))
            {
                if let Err(error) = delete_binding(libvirt_uri, &tap) {
                    warn!(%tap, %error, "failed to remove orphaned nwfilter binding");
                    libvirt = false;
                    first_error.get_or_insert(error);
                } else {
                    info!(%tap, %vm_id, "removed orphaned nwfilter binding");
                }
            }
            continue;
        }
        match remove_interface_in_pass(libvirt_uri, &tap, &mut libvirt) {
            // Keep going after a failure. Stopping at the first one would leave
            // the rest of a VM's interfaces behind over one that is stuck.
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
        None => Ok((removed, incomplete)),
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
    let bindings = existing_bindings(libvirt_uri);
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
                bound: bindings
                    .as_ref()
                    .is_some_and(|bindings| bindings.contains(&tap)),
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
                bound: true,
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
/// call. Every mutating operation holds the operation lock, so an unbounded
/// call here would let one unreachable libvirt stall every other VM's prepare
/// and remove behind it.
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
fn existing_bindings(uri: &str) -> Option<HashSet<String>> {
    match virsh_output(uri, &["nwfilter-binding-list"], None) {
        Ok(output) => Some(
            output
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .filter(|name| is_managed_name(name))
                .map(str::to_string)
                .collect(),
        ),
        Err(error) => {
            debug!("could not list nwfilter bindings: {error:#}");
            None
        }
    }
}

fn run_command(program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<()> {
    run_command_with_timeout(program, args, stdin, COMMAND_TIMEOUT).map(|_| ())
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
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
/// The VMM's side of this protocol -- what it falls back to, what it refuses,
/// what it does when the answer is missing -- had no test at all, because
/// every path needed a privileged daemon. It does not: it needs something that
/// answers on a socket. This is that, scripted per behaviour, recording what
/// it was asked so a test can assert on the conversation rather than on its
/// effects.
#[cfg(test)]
pub(crate) mod testing {
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use serde_json::{json, Value};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    /// How the fake answers.
    #[derive(Debug, Clone)]
    pub(crate) enum Behavior {
        /// Answers `hello` with the given operations, and every listed
        /// operation with a plausible success.
        Capable {
            operations: Vec<String>,
            ingress: bool,
            /// Whether it claims to record who an interface belongs to.
            attribution: bool,
        },
        /// Reached, but predates `hello`: every unknown operation is an error,
        /// exactly as `serde` produces one.
        Legacy,
    }

    impl Behavior {
        pub(crate) fn capable(operations: &[&str]) -> Self {
            Self::Capable {
                operations: operations.iter().map(|name| name.to_string()).collect(),
                ingress: false,
                attribution: true,
            }
        }

        pub(crate) fn forwarding(operations: &[&str]) -> Self {
            match Self::capable(operations) {
                Self::Capable { operations, .. } => Self::Capable {
                    operations,
                    ingress: true,
                    attribution: true,
                },
                other => other,
            }
        }
    }

    pub(crate) struct FakeNetd {
        _dir: tempfile::TempDir,
        socket: PathBuf,
        seen: Arc<Mutex<Vec<Value>>>,
    }

    impl FakeNetd {
        pub(crate) fn spawn(behavior: Behavior) -> Self {
            Self::spawn_holding(behavior, Vec::new())
        }

        /// A netd that holds these interfaces, whatever else it does.
        pub(crate) fn spawn_holding(behavior: Behavior, interfaces: Vec<Value>) -> Self {
            Self::start(behavior, interfaces)
        }

        fn start(behavior: Behavior, interfaces: Vec<Value>) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let socket = dir.path().join("netd.sock");
            let listener = UnixListener::bind(&socket).expect("bind");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorder = seen.clone();
            let interfaces = std::sync::Arc::new(interfaces);
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let behavior = behavior.clone();
                    let interfaces = interfaces.clone();
                    let recorder = recorder.clone();
                    tokio::spawn(async move {
                        let mut message = Vec::new();
                        if stream.read_to_end(&mut message).await.is_err() {
                            return;
                        }
                        let Ok(request) = serde_json::from_slice::<Value>(&message) else {
                            return;
                        };
                        recorder.lock().expect("poisoned").push(request.clone());
                        let response = answer(&behavior, &interfaces, &request);
                        let _ = stream
                            .write_all(&serde_json::to_vec(&response).unwrap())
                            .await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self {
                _dir: dir,
                socket,
                seen,
            }
        }

        pub(crate) fn socket(&self) -> &Path {
            &self.socket
        }

        /// Every request it was sent, in order.
        pub(crate) fn seen(&self) -> Vec<Value> {
            self.seen.lock().expect("poisoned").clone()
        }

        pub(crate) fn operations(&self) -> Vec<String> {
            self.seen()
                .iter()
                .map(|request| request["operation"].as_str().unwrap_or("?").to_string())
                .collect()
        }
    }

    fn answer(behavior: &Behavior, interfaces: &[Value], request: &Value) -> Value {
        let operation = request["operation"].as_str().unwrap_or_default();
        let (operations, ingress, attribution) = match behavior {
            Behavior::Legacy => {
                return match operation {
                    // What the real thing answers for an operation it knows.
                    "prepare_bridge" | "prepare_macvtap" | "remove" | "check" => {
                        json!({"ok": true, "tap": "dtdeadbeef00"})
                    }
                    other => json!({
                        "ok": false,
                        "error": format!("invalid netd request: unknown variant `{other}`"),
                    }),
                };
            }
            Behavior::Capable {
                operations,
                ingress,
                attribution,
            } => (operations, *ingress, *attribution),
        };
        if !operations.iter().any(|name| name == operation) {
            return json!({
                "ok": false,
                "error": format!("invalid netd request: unknown variant `{operation}`"),
            });
        }
        match operation {
            "hello" => json!({
                "ok": true,
                "capabilities": {
                    "version": "fake-netd",
                    "operations": operations,
                    "ingress": ingress,
                    "attribution": attribution,
                },
            }),
            "prepare_bridge" | "prepare_macvtap" => {
                let mut response = json!({
                    "ok": true,
                    "tap": "dtdeadbeef00",
                    "queues": request["queues"].as_u64().unwrap_or(1).max(1),
                });
                if ingress {
                    let asked = request["ingress"].as_array().cloned().unwrap_or_default();
                    response["ingress"] = Value::Array(asked);
                }
                response
            }
            "remove" | "check" => json!({"ok": true, "tap": "dtdeadbeef00"}),
            "remove_all" => json!({"ok": true, "removed": 0, "incomplete": false}),
            "list" => {
                let instance = request["instance_id"].as_str().unwrap_or_default();
                let held: Vec<Value> = interfaces
                    .iter()
                    .filter(|record| {
                        instance.is_empty() || record["instance_id"].as_str() == Some(instance)
                    })
                    .cloned()
                    .collect();
                json!({"ok": true, "interfaces": held})
            }
            "remove_interface" => json!({"ok": true, "tap": request["tap"]}),
            _ => json!({"ok": true}),
        }
    }
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
            serve_connection(&std::sync::Arc::new(NetdConfig::default()), &mut server),
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
        serve_connection(&std::sync::Arc::new(NetdConfig::default()), &mut server)
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
    fn the_workdir_travels_but_older_callers_may_omit_it() {
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
        // It is a log line, not an input, so a caller that never sets it is not
        // asking for anything different.
        let Request::PrepareBridge(decoded) = decode_minimal_bridge() else {
            panic!("expected a bridge prepare");
        };
        assert_eq!(decoded.workdir, "");
    }

    #[test]
    fn host_ports_travel_with_the_bridge_prepare_and_default_to_none() {
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

        let Request::PrepareBridge(decoded) = decode_minimal_bridge() else {
            panic!("expected a bridge prepare");
        };
        assert!(decoded.ingress.is_empty());
    }

    #[test]
    fn saying_nothing_about_ports_is_how_a_netd_reports_it_forwards_none() {
        // The same reading `queues` gets: absent distinguishes "this netd does
        // not do that" from "nothing was asked for", so ports are never assumed
        // forwarded just because the TAP came back.
        let response: Response = serde_json::from_value(serde_json::json!({
            "ok": true,
            "tap": "dt000000000000",
        }))
        .unwrap();
        assert!(response.ingress.is_none());

        let response: Response = serde_json::from_value(serde_json::json!({
            "ok": true,
            "tap": "dt000000000000",
            "ingress": [{
                "protocol": "udp",
                "host_address": "0.0.0.0",
                "host_port": 7483,
                "guest_port": 51820,
            }],
        }))
        .unwrap();
        assert_eq!(response.ingress.unwrap().len(), 1);
    }

    /// A prepare carrying only the fields that predate this change.
    fn decode_minimal_bridge() -> Request {
        serde_json::from_value(serde_json::json!({
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
        .unwrap()
    }

    #[test]
    fn a_whole_vm_sweep_needs_no_record_of_what_it_is_deleting() {
        let value = serde_json::to_value(Request::RemoveAll {
            instance_id: "instance".into(),
            vm_id: "vm".into(),
        })
        .unwrap();
        assert_eq!(value["operation"], "remove_all");
        assert_eq!(value["instance_id"], "instance");
        assert_eq!(value["vm_id"], "vm");
        // No NIC index: the point is reaching the ones the caller can no longer
        // name, so it names none and netd derives the whole space instead.
        assert!(value.get("nic_index").is_none());

        // That space is bounded by what an identity may say, which is what
        // makes deriving it cheap enough to do on every launch.
        let mut identity = identity("instance", "vm", MAX_NIC_INDEX);
        assert!(validate_identity(&identity).is_ok());
        identity.nic_index = MAX_NIC_INDEX + 1;
        assert!(validate_identity(&identity).is_err());
    }

    /// A sweep names no single interface, so its answer must not carry an
    /// empty one. `request()` reads a blank `tap` as a malformed response, and
    /// a third-party netd copying this shape would have to send a field that
    /// means nothing.
    #[test]
    fn a_sweep_reports_a_count_and_no_interface() {
        let value = serde_json::to_value(
            Outcome::Swept {
                removed: 3,
                incomplete: false,
            }
            .into_response(),
        )
        .unwrap();
        assert_eq!(value["removed"], 3);
        assert!(value.get("tap").is_none());

        // A prepare still names one, because the caller hands that name to QEMU.
        let value = serde_json::to_value(Outcome::tap("dtabc".into()).into_response()).unwrap();
        assert_eq!(value["tap"], "dtabc");
        assert!(value.get("removed").is_none());
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
    /// A netd that answers a sweep with no count did not sweep. Reading the
    /// absent field as zero is the same conflation `queues` and `ingress` are
    /// shaped to avoid, and here it would report a netd that cannot collect a
    /// VM's interfaces as a VM that had none.
    #[tokio::test]
    async fn a_sweep_without_a_count_is_not_read_as_an_empty_one() {
        // Claims the operation, answers without the field.
        let netd = testing::FakeNetd::spawn(testing::Behavior::capable(&["hello"]));
        let error = remove_all(netd.socket(), "instance", "vm")
            .await
            .expect_err("an answer with no count is not a successful sweep");
        assert!(!is_unreachable(&error));

        let netd = testing::FakeNetd::spawn(testing::Behavior::capable(&["hello", "remove_all"]));
        let sweep = remove_all(netd.socket(), "instance", "vm").await.unwrap();
        assert_eq!(sweep.removed, 0);
        assert!(!sweep.incomplete);
    }

    /// Every "an unreachable netd is not a failure" branch in the VMM hangs
    /// off this one predicate, and a marker attached as context is not a link
    /// in the source chain.
    #[test]
    fn an_unreachable_netd_is_recognized_through_the_contexts_stacked_on_it() {
        let error = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context(Unreachable)
            .context("failed to connect to netd at /run/netd.sock")
            .context("failed to prepare netd-managed networking");
        assert!(is_unreachable(&error));

        let other = anyhow::anyhow!("netd remove_all failed: no such bridge")
            .context("failed to prepare netd-managed networking");
        assert!(!is_unreachable(&other));
    }

    #[tokio::test]
    async fn a_probe_tells_absent_from_old_from_answering() {
        assert!(matches!(
            probe(Path::new("/nonexistent/netd.sock")).await,
            Reachability::Unreachable
        ));

        let legacy = testing::FakeNetd::spawn(testing::Behavior::Legacy);
        let reachability = probe(legacy.socket()).await;
        assert!(matches!(reachability, Reachability::Legacy));
        // Reached, so a caller must not treat it as absent -- but it can do
        // nothing this netd was not already able to do.
        assert!(reachability.is_reachable());
        assert!(!reachability.supports("remove_all"));
        assert!(!reachability.forwards_ingress());

        let netd =
            testing::FakeNetd::spawn(testing::Behavior::forwarding(&["hello", "remove_all"]));
        let reachability = probe(netd.socket()).await;
        assert!(reachability.supports("remove_all"));
        assert!(!reachability.supports("gc"));
        assert!(reachability.forwards_ingress());
    }

    /// The whole point of asking: a caller must be able to tell an operation
    /// this netd does not have from one that failed, and the two look the same
    /// in an error message.
    #[test]
    fn a_probe_reports_what_this_netd_can_do() {
        let value = serde_json::to_value(&Request::Hello).unwrap();
        assert_eq!(value["operation"], "hello");

        let response = Outcome::Hello(capabilities()).into_response();
        let capabilities = response.capabilities.expect("hello answers capabilities");
        assert!(capabilities.supports("remove_all"));
        assert!(capabilities.supports("hello"));
        assert!(!capabilities.supports("forward_the_whole_internet"));
        // This netd builds interfaces and does not forward host ports. Saying
        // so before a prepare is what lets deployment refuse a mapping it
        // cannot honour, instead of a launch warning about it afterwards.
        assert!(!capabilities.ingress);
        assert!(capabilities.attribution);

        // Absent capabilities is an older netd, not one that can do nothing.
        let legacy: Response = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(legacy.capabilities.is_none());
    }
}
