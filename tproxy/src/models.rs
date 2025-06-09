use rinja::Template;
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Iter, BTreeMap},
    net::Ipv4Addr,
    time::SystemTime,
};
use tproxy_rpc::{AcmeInfoResponse, HostInfo as PbHostInfo};

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
    pub last_seen: SystemTime,
}

#[derive(Template)]
#[template(path = "wg.conf", escape = "none")]
pub struct WgConf<'a> {
    pub private_key: &'a str,
    pub listen_port: u16,
    pub peers: MapValues<'a, String, InstanceInfo>,
}

#[derive(Template)]
#[template(path = "cvmlist.html")]
pub struct CvmList<'a> {
    pub hosts: &'a [PbHostInfo],
    pub acme_info: &'a AcmeInfoResponse,
}
