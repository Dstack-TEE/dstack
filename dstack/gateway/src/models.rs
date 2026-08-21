// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_gateway_rpc::{AcmeInfoResponse, ProxyAccelStatus, StatusResponse};
use rinja::Template;
use serde::{Deserialize, Serialize};
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::SystemTime,
};

use crate::kv::PortPolicy;

mod filters {
    pub fn hex(data: impl AsRef<[u8]>) -> rinja::Result<String> {
        Ok(hex::encode(data))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceInfo {
    pub id: String,
    pub app_id: String,
    pub ip: Ipv4Addr,
    pub public_key: String,
    pub reg_time: SystemTime,
    /// Port policy. `None` means the CVM didn't report any (legacy);
    /// gateway will lazily populate via Info() on first proxied connection.
    #[serde(default)]
    pub port_policy: Option<PortPolicy>,
    /// Hex-encoded compose_hash that `port_policy` was learned against. The
    /// cache is invalidated when a new registration presents a different hash.
    #[serde(default)]
    pub port_policy_hash: String,
    /// Operator-set override (Admin RPC). Takes precedence over `port_policy`
    /// when set; survives app upgrades.
    #[serde(default)]
    pub admin_port_policy: Option<PortPolicy>,
    /// Operator-set traffic gate (Admin RPC). `None` means no operator ever
    /// touched it. See [`InstanceInfo::is_admin_ready`].
    ///
    /// Persisted as a field of the instance record; see
    /// [`crate::kv::InstanceData::admin_ready`] for why it does not get a key
    /// of its own.
    #[serde(default)]
    pub admin_ready: Option<bool>,
    /// Whether this CVM asked for its traffic to be gated on app health, as
    /// declared at registration. Persisted, so a gateway restart does not start
    /// polling an app that never opted in and conclude from the failures that
    /// it is unhealthy.
    #[serde(default)]
    pub health_check: bool,
    /// Application-level health, as last observed by *this* gateway node.
    ///
    /// Deliberately not persisted and not shared through WaveKV. Every node
    /// polls for itself, the same way each node reads its own WireGuard
    /// handshakes -- a shared "healthy" flag would outlive the instance that
    /// set it, and "I could not reach it" is a per-node fact anyway.
    #[serde(skip)]
    pub health: HealthState,
    #[serde(skip)]
    pub connections: Arc<AtomicU64>,
}

/// What a CVM reported about itself when it registered.
///
/// Bundled rather than passed as positional arguments: every one of these is a
/// self-declared capability, and the list has already grown once. A struct
/// keeps the next addition from rippling through every call site.
#[derive(Debug, Clone, Default)]
pub struct ReportedCapabilities {
    /// Per-port behaviour declared by the app. `None` means "not reported"
    /// (legacy CVM), and the gateway fetches it lazily instead.
    pub port_policy: Option<PortPolicy>,
    /// Whether the app asked for its traffic to be gated on its health
    /// (`requirements.health_check.enabled`).
    ///
    /// `None` means the caller has nothing to say about it -- the debug
    /// registration path, which has no CVM to ask -- and leaves whatever the
    /// instance already declared in place. `Some(false)` is an app that did not
    /// opt in, or an image that predates the field; the gateway polls neither.
    pub health_check: Option<bool>,
}

impl From<Option<PortPolicy>> for ReportedCapabilities {
    /// Convenience for callers that only have a port policy to report and
    /// nothing to say about health gating.
    fn from(port_policy: Option<PortPolicy>) -> Self {
        Self {
            port_policy,
            health_check: None,
        }
    }
}

/// What this gateway node knows about an instance's application-level health.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    /// No poll has completed yet. Reads as *not* healthy: a CVM registers
    /// during boot, before its containers exist, so "not asked yet" is far
    /// more often "not up yet" than "fine".
    #[default]
    Unknown,
    /// The guest agent reported that every container declaring a healthcheck
    /// is healthy.
    Healthy,
    /// The guest agent reported at least one container not healthy, or could
    /// not be reached at all.
    Unhealthy,
    /// This instance never asked to be gated -- an app that did not set
    /// `requirements.health_check.enabled`, or an image that predates the
    /// field. Reads as healthy: it has to keep serving exactly as before.
    Ungated,
}

impl HealthState {
    /// The state an instance starts in, given whether it asked to be gated.
    ///
    /// An instance that opted in starts `Unknown` -- held out of rotation until
    /// a poll answers -- because registration happens during boot, before the
    /// app exists. One that did not starts `Ungated` and stays eligible, so
    /// apps that never asked for this keep working.
    pub fn initial(health_check: bool) -> Self {
        if health_check {
            HealthState::Unknown
        } else {
            HealthState::Ungated
        }
    }

    /// Whether this state permits traffic.
    pub fn is_healthy(self) -> bool {
        matches!(self, HealthState::Healthy | HealthState::Ungated)
    }

    /// Stable lowercase name, as reported over the admin API.
    pub fn as_str(self) -> &'static str {
        match self {
            HealthState::Unknown => "unknown",
            HealthState::Healthy => "healthy",
            HealthState::Unhealthy => "unhealthy",
            HealthState::Ungated => "ungated",
        }
    }
}

impl InstanceInfo {
    pub fn num_connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Whether an operator has left this instance eligible for traffic.
    ///
    /// Defaults to ready, so the gate is invisible until someone explicitly
    /// closes it -- an instance that predates this field, or one nobody has
    /// touched, keeps serving exactly as before.
    ///
    /// This only gates *multi-target* selection, i.e. connections addressed to
    /// the app id. Routing to the instance id directly ignores it on purpose:
    /// the point of taking an instance out of rotation is to investigate it
    /// while it is still running, which needs the instance to stay reachable.
    pub fn is_admin_ready(&self) -> bool {
        self.admin_ready.unwrap_or(true)
    }

    /// Whether this node's last health observation permits traffic.
    ///
    /// Unlike [`InstanceInfo::is_admin_ready`], this is an inference and can be
    /// wrong, so callers fail open when it would empty an app's candidate set.
    pub fn is_healthy(&self) -> bool {
        self.health.is_healthy()
    }

    /// Whether replacing `self` with `other` could invalidate a cached
    /// selection.
    ///
    /// `ip` is copied straight into the cached `AddressInfo`; `app_id` decides
    /// which cache entry the instance belongs to; `public_key` is the key the
    /// handshake freshness filter looks up; `admin_ready` and `health` both
    /// gate eligibility. A change to any of them means a cached `top_n` was
    /// computed against a record that no longer exists.
    ///
    /// `health` is this node's own observation rather than something the record
    /// carries, and a reload copies it across, so it only differs here when the
    /// reload had to reset it -- the declared capability changed, meaning the
    /// image did.
    pub fn routing_inputs_differ(&self, other: &Self) -> bool {
        self.ip != other.ip
            || self.app_id != other.app_id
            || self.public_key != other.public_key
            || self.admin_ready != other.admin_ready
            || self.health != other.health
    }
}

/// Snapshot of an instance's port-policy state for admin inspection.
#[derive(Debug, Clone)]
pub struct PortPolicyView {
    /// What the instance most recently reported (registration or lazy fetch).
    pub instance_reported: Option<PortPolicy>,
    /// What the operator set via Admin RPC, if any.
    pub admin_override: Option<PortPolicy>,
}

impl PortPolicyView {
    /// The policy the proxy will actually enforce (admin override wins).
    pub fn effective(&self) -> Option<&PortPolicy> {
        self.admin_override
            .as_ref()
            .or(self.instance_reported.as_ref())
    }

    /// `"admin"`, `"instance"`, or `"none"`.
    pub fn source(&self) -> &'static str {
        if self.admin_override.is_some() {
            "admin"
        } else if self.instance_reported.is_some() {
            "instance"
        } else {
            "none"
        }
    }
}

pub trait Counting {
    fn inc(&self);
    fn dec(&self);
    fn enter(self) -> EnteredCounter<Self>
    where
        Self: Sized,
    {
        EnteredCounter::new(self)
    }
}

impl Counting for Arc<AtomicU64> {
    fn inc(&self) {
        self.fetch_add(1, Ordering::Relaxed);
    }
    fn dec(&self) {
        self.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Counting for &'_ AtomicU64 {
    fn inc(&self) {
        self.fetch_add(1, Ordering::Relaxed);
    }
    fn dec(&self) {
        self.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct EnteredCounter<C: Counting = Arc<AtomicU64>>(C);
impl<C: Counting> EnteredCounter<C> {
    pub fn new(connections: C) -> Self {
        connections.inc();
        Self(connections)
    }
}
impl<C: Counting> Drop for EnteredCounter<C> {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// One `[Peer]` stanza of the rendered WireGuard config.
///
/// Built by the caller rather than borrowed straight from the instance table so
/// that a record `wg` would refuse can be left out — the template renders with
/// `escape = "none"`, and `wg syncconf` rejects the whole file on one bad line.
pub struct WgPeer<'a> {
    pub public_key: &'a str,
    pub ip: Ipv4Addr,
}

#[derive(Template)]
#[template(path = "wg.conf", escape = "none")]
pub struct WgConf<'a> {
    pub private_key: &'a str,
    pub listen_port: u16,
    pub peers: Vec<WgPeer<'a>>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct Dashboard {
    pub status: StatusResponse,
    pub acme_info: AcmeInfoResponse,
    /// Lifted out of `status` so the template does not have to unwrap the
    /// proto's optional message on every field.
    pub accel: ProxyAccelStatus,
}
