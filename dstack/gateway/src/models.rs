// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_gateway_rpc::{AcmeInfoResponse, ProxyAccelStatus, StatusResponse};
use rinja::Template;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, btree_map::Iter},
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use crate::kv::PortPolicy;

mod filters {
    pub fn hex(data: impl AsRef<[u8]>) -> rinja::Result<String> {
        Ok(hex::encode(data))
    }
}

pub struct MapValues<'a, K, V>(pub &'a BTreeMap<K, V>);
impl<K, V> Copy for MapValues<'_, K, V> {}
impl<K, V> Clone for MapValues<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, K, V> From<&'a BTreeMap<K, V>> for MapValues<'a, K, V> {
    fn from(map: &'a BTreeMap<K, V>) -> Self {
        MapValues(map)
    }
}

pub struct MapValuesIter<'a, K, V>(Iter<'a, K, V>);

impl<'a, K, V> IntoIterator for MapValues<'a, K, V> {
    type Item = &'a V;
    type IntoIter = MapValuesIter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        MapValuesIter(self.0.iter())
    }
}

impl<'a, K, V> Iterator for MapValuesIter<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(_, v)| v)
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
    #[serde(skip)]
    pub connections: Arc<AtomicU64>,
}

impl InstanceInfo {
    pub fn num_connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
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

#[derive(Template)]
#[template(path = "wg.conf", escape = "none")]
pub struct WgConf<'a> {
    pub private_key: &'a str,
    pub listen_port: u16,
    pub peers: MapValues<'a, String, InstanceInfo>,
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
    use super::{Counting as _, Dashboard, MapValues, PortPolicyView};
    use crate::kv::{PortFlags, PortPolicy};
    use dstack_gateway_rpc::{AcmeInfoResponse, HostInfo, StatusResponse};
    use rinja::Template as _;
    use std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    #[test]
    fn internal_models_matrix() {
        let connections = Arc::new(AtomicU64::new(0));
        {
            let _outer = connections.clone().enter();
            assert_eq!(connections.load(Ordering::Relaxed), 1);
            {
                let _inner = connections.clone().enter();
                assert_eq!(connections.load(Ordering::Relaxed), 2);
            }
            assert_eq!(connections.load(Ordering::Relaxed), 1);
        }
        assert_eq!(connections.load(Ordering::Relaxed), 0);

        let unwind_counter = connections.clone();
        let result = std::panic::catch_unwind(move || {
            let _guard = unwind_counter.enter();
            panic!("exercise unwind cleanup");
        });
        assert!(result.is_err());
        assert_eq!(connections.load(Ordering::Relaxed), 0);

        let instance_policy = PortPolicy {
            ports: BTreeMap::from([(443, PortFlags { pp: false })]),
            restrict_mode: false,
        };
        let admin_policy = PortPolicy {
            ports: BTreeMap::from([(8443, PortFlags { pp: true })]),
            restrict_mode: true,
        };
        let view = PortPolicyView {
            instance_reported: Some(instance_policy.clone()),
            admin_override: Some(admin_policy.clone()),
        };
        assert_eq!(view.effective(), Some(&admin_policy));
        assert_eq!(view.source(), "admin");

        let instance_only = PortPolicyView {
            instance_reported: Some(instance_policy.clone()),
            admin_override: None,
        };
        assert_eq!(instance_only.effective(), Some(&instance_policy));
        assert_eq!(instance_only.source(), "instance");

        let no_policy = PortPolicyView {
            instance_reported: None,
            admin_override: None,
        };
        assert_eq!(no_policy.effective(), None);
        assert_eq!(no_policy.source(), "none");

        let ordered = BTreeMap::from([("charlie", 3_u8), ("alpha", 1_u8), ("bravo", 2_u8)]);
        let values: Vec<_> = MapValues::from(&ordered).into_iter().copied().collect();
        assert_eq!(values, vec![1, 2, 3]);

        let hostile = "<script>dashboard-sentinel</script>";
        let benign = "dashboard-benign-app";
        let dashboard = Dashboard {
            status: StatusResponse {
                url: hostile.into(),
                hosts: vec![HostInfo {
                    instance_id: hostile.into(),
                    app_id: benign.into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            acme_info: AcmeInfoResponse::default(),
        };
        let rendered = dashboard.render().expect("dashboard must render");
        assert!(!rendered.contains(hostile));
        assert!(rendered.contains("&#60;script&#62;dashboard-sentinel&#60;/script&#62;"));
        assert!(rendered.contains(benign));
    }
}
