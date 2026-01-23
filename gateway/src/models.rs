// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_gateway_rpc::{AcmeInfoResponse, StatusResponse};
use rinja::Template;
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Iter, BTreeMap},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::SystemTime,
};

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
    #[serde(skip)]
    pub connections: Arc<AtomicU64>,
}

impl InstanceInfo {
    pub fn num_connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
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
}
