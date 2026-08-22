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
    /// touched it. See [`InstanceInfo::is_ready`].
    ///
    /// Persisted as a field of the instance record; see
    /// [`crate::kv::InstanceData::ready`] for why it does not get a key
    /// of its own.
    #[serde(default)]
    pub ready: Option<bool>,
    /// What this CVM asked for, and what this node has observed since.
    ///
    /// Serialized as the bare `health_check` boolean it was before, because the
    /// observation is deliberately not persisted and not shared through WaveKV:
    /// every node polls for itself, the same way each node reads its own
    /// WireGuard handshakes. A shared "healthy" flag would outlive the instance
    /// that set it, and "I could not reach it" is a per-node fact anyway.
    ///
    /// The field is crate-visible so a record can be built in one expression;
    /// [`Health`]'s own state is not, so there is no way to build one whose
    /// declaration and verdict disagree.
    #[serde(default, rename = "health_check")]
    pub(crate) health: Health,
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
    /// (`requirements.health_check`).
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
    /// `requirements.health_check`, or an image that predates the
    /// field. Reads as healthy: it has to keep serving exactly as before.
    Ungated,
}

/// An instance's health gating: what the CVM asked for, and what this node has
/// observed since.
///
/// One value rather than two fields, because the second is a function of the
/// first whenever there is no observation to report -- `Ungated` is not a
/// verdict, it is a restatement of "never asked". Kept apart, that derivation
/// has to be repeated at every site that builds or resets a record, and a site
/// that forgets produces an instance which is simultaneously routable and
/// unpollable, with nothing on this node able to lift it.
///
/// Serialized as the bare boolean, so the stored record keeps the shape it had:
/// only the declaration is persisted, and the observation is re-derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "bool", into = "bool")]
pub struct Health {
    gated: bool,
    state: HealthState,
}

impl Default for Health {
    /// Not derived. `HealthState::default()` is `Unknown`, but the default
    /// *declaration* is "not gated", whose state is `Ungated` -- and a derive
    /// would pair the two independently and produce an instance that is held
    /// out of rotation while also being filtered out of the poll set, with
    /// nothing able to lift it. Deferring to `From<bool>` keeps one derivation.
    fn default() -> Self {
        Self::from(false)
    }
}

impl From<bool> for Health {
    fn from(gated: bool) -> Self {
        Self {
            gated,
            state: HealthState::initial(gated),
        }
    }
}

impl From<Health> for bool {
    fn from(health: Health) -> Self {
        health.gated
    }
}

impl Health {
    /// Whether this instance asked to be gated, and therefore polled.
    pub fn is_gated(self) -> bool {
        self.gated
    }

    /// The last observation, or the state that stands in for never having one.
    pub fn state(self) -> HealthState {
        self.state
    }

    /// Record what a poll found.
    fn observe(&mut self, state: HealthState) {
        self.state = state;
    }

    /// Apply what the CVM declared at registration.
    ///
    /// A declaration that changed means the image did, so any verdict about the
    /// previous one is void. An unchanged one must not disturb a live verdict:
    /// a CVM re-registers every three minutes without going anywhere, and
    /// resetting on each would drop a healthy instance out of rotation until
    /// its next poll, forever, on a timer.
    fn declare(&mut self, gated: bool) {
        if self.gated != gated {
            self.gated = gated;
            self.forget();
        }
    }

    /// Drop any verdict, as if the instance had just registered.
    fn forget(&mut self) {
        self.state = HealthState::initial(self.gated);
    }
}

impl HealthState {
    /// The state an instance starts in, given whether it asked to be gated.
    ///
    /// An instance that opted in starts `Unknown` -- held out of rotation until
    /// a poll answers -- because registration happens during boot, before the
    /// app exists. One that did not starts `Ungated` and stays eligible, so
    /// apps that never asked for this keep working.
    fn initial(health_check: bool) -> Self {
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
    pub fn is_ready(&self) -> bool {
        self.ready.unwrap_or(true)
    }

    /// Whether this node's last health observation permits traffic.
    ///
    /// Unlike [`InstanceInfo::is_ready`], this is an inference and can be
    /// wrong, so callers fail open when it would empty an app's candidate set.
    pub fn is_healthy(&self) -> bool {
        self.health.state().is_healthy()
    }

    /// This node's last health observation, for reporting.
    pub fn health(&self) -> HealthState {
        self.health.state()
    }

    /// Whether this instance asked to be gated, and polled, at all.
    pub fn health_check(&self) -> bool {
        self.health.is_gated()
    }

    /// Record a fresh observation.
    pub fn set_health(&mut self, state: HealthState) {
        self.health.observe(state);
    }

    /// Apply what the CVM declared, re-deriving the verdict if it changed.
    pub fn set_health_check(&mut self, health_check: bool) {
        self.health.declare(health_check);
    }

    /// Forget any verdict, as if the instance had just registered.
    ///
    /// For the caller that can see a *reboot* -- a new WireGuard key -- which
    /// the declaration alone cannot show.
    pub fn reset_health(&mut self) {
        self.health.forget();
    }

    /// Adopt another record's verdict, when it is about the same running app.
    ///
    /// Used by the reload path: health is this node's own observation and the
    /// store does not carry it, so re-deriving it from the record would reset
    /// the whole fleet to `Unknown` on every sync round. Two things must not
    /// survive. A changed declaration means the image was replaced. And a
    /// changed WireGuard key means the CVM rebooted: the guest caches its key
    /// store in `/run`, which is tmpfs, so a fresh key is a fresh boot. Without
    /// the second check the reboot reset is only applied on whichever node took
    /// the registration -- every *other* node learns about the new boot through
    /// sync and quietly copies its own pre-reboot verdict onto it.
    pub fn inherit_health_from(&mut self, previous: &Self) {
        if self.health_check() == previous.health_check() && self.public_key == previous.public_key
        {
            self.health.observe(previous.health.state());
        }
    }

    /// Whether replacing `self` with `other` could invalidate a cached
    /// selection.
    ///
    /// `ip` is copied straight into the cached `AddressInfo`; `app_id` decides
    /// which cache entry the instance belongs to; `public_key` is the key the
    /// handshake freshness filter looks up; `ready` and `health` both
    /// gate eligibility. A change to any of them means a cached `top_n` was
    /// computed against a record that no longer exists.
    ///
    /// `health` is this node's own observation rather than something the record
    /// carries, and a reload copies it across, so it only differs here when the
    /// reload had to reset it -- the declared capability changed, meaning the
    /// image did.
    pub fn routing_inputs_differ(&self, other: &Self) -> bool {
        self.routing_inputs() != other.routing_inputs()
    }

    /// The parts of this record a cached selection was computed from.
    ///
    /// Borrows rather than clones, so an in-place edit can be checked for
    /// staleness without copying a record it may not have changed -- this runs
    /// once per poll result, which is the whole fleet every interval.
    pub(crate) fn routing_inputs(&self) -> RoutingInputs<'_> {
        RoutingInputs {
            ip: self.ip,
            app_id: &self.app_id,
            public_key: &self.public_key,
            ready: self.ready,
            health: self.health,
        }
    }
}

/// A borrowed view of the fields [`InstanceInfo::routing_inputs_differ`]
/// compares, so that definition lives in exactly one place. Adding a field to
/// the selection means adding it here; nothing else has to be audited.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoutingInputs<'a> {
    ip: Ipv4Addr,
    app_id: &'a str,
    public_key: &'a str,
    ready: Option<bool>,
    health: Health,
}

impl RoutingInputs<'_> {
    /// Detach from the record, so a caller can compare across a mutation.
    pub(crate) fn to_owned(self) -> OwnedRoutingInputs {
        OwnedRoutingInputs {
            ip: self.ip,
            app_id: self.app_id.to_string(),
            public_key: self.public_key.to_string(),
            ready: self.ready,
            health: self.health,
        }
    }
}

/// [`RoutingInputs`] with the borrows taken, for comparing a record against
/// itself either side of an edit.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OwnedRoutingInputs {
    ip: Ipv4Addr,
    /// Which cache entry the record belonged to *before* the edit. A record
    /// that changed apps invalidates both.
    pub(crate) app_id: String,
    public_key: String,
    ready: Option<bool>,
    health: Health,
}

impl PartialEq<RoutingInputs<'_>> for OwnedRoutingInputs {
    fn eq(&self, other: &RoutingInputs<'_>) -> bool {
        self.ip == other.ip
            && self.app_id == other.app_id
            && self.public_key == other.public_key
            && self.ready == other.ready
            && self.health == other.health
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored record's shape is unchanged by folding the two health fields
    /// into one value. A record written by an older build has to keep loading,
    /// and a record this build writes has to keep loading on an older one --
    /// which is a downgrade, i.e. exactly when nobody is watching.
    #[test]
    fn health_is_stored_as_the_bare_declaration() {
        let gated = serde_json::to_value(Health::from(true)).expect("serialize");
        assert_eq!(gated, serde_json::json!(true));

        let restored: Health = serde_json::from_value(serde_json::json!(true)).expect("parse");
        assert!(restored.is_gated());
        // Not `Healthy`. The observation is deliberately not carried, so a
        // record that arrives from disk has to start held out of rotation
        // rather than inherit a verdict nobody made.
        assert_eq!(restored.state(), HealthState::Unknown);
    }

    /// The pair cannot be built inconsistently, which is the point of it being
    /// one value. `HealthState::default()` is `Unknown` while the default
    /// declaration is "not gated", whose state is `Ungated` -- a derived
    /// `Default` would pair those and produce an instance that is both held out
    /// of rotation and filtered out of the poll set, with nothing able to lift
    /// it.
    #[test]
    fn the_default_declaration_is_not_the_default_state() {
        assert_eq!(Health::default(), Health::from(false));
        assert_eq!(Health::default().state(), HealthState::Ungated);
        assert!(Health::default().state().is_healthy());
    }

    /// A CVM re-registers every three minutes without having gone anywhere.
    /// Re-deriving the verdict on each would drop a healthy instance out of
    /// rotation until its next poll, forever, on a timer.
    #[test]
    fn redeclaring_the_same_intent_leaves_a_verdict_alone() {
        let mut health = Health::from(true);
        health.observe(HealthState::Healthy);

        health.declare(true);
        assert_eq!(health.state(), HealthState::Healthy);

        // A changed declaration means a different image, so the verdict is
        // about something that is no longer running.
        health.declare(false);
        assert_eq!(health.state(), HealthState::Ungated);
    }
}
