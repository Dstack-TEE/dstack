// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `/metrics` scrape handler.

use std::sync::atomic::Ordering;

use rocket::State;

use crate::{
    main_service::Proxy,
    metrics::{self, PeerSnapshot, Snapshot, StoreSnapshot},
    proxy::{stats::accel_status, NUM_CONNECTIONS},
};

pub fn render(state: &State<Proxy>) -> String {
    metrics::render(&sample(state))
}

fn sample(state: &State<Proxy>) -> Snapshot {
    let kv_store = state.kv_store().clone();
    let accel = accel_status(&state.config.proxy);

    // The public data path takes this lock on every connection, so the scrape
    // holds it for one O(1) count and nothing else.
    //
    // The node counts deliberately do not go through `get_all_nodes()` /
    // `get_active_nodes()`: those read no proxy state at all -- only
    // `self.kv_store` -- so routing them through the lock would drag two loads
    // of the node table, a `GatewayNodeInfo` per node, and one ephemeral-lock
    // acquisition per node for an unused `last_seen` in here with them.
    let instances = state.lock().state.instances.len() as u64;
    let (nodes_total, nodes_active) = kv_store.count_nodes();

    let stores = vec![
        store_snapshot("persistent", kv_store.persistent()),
        store_snapshot("ephemeral", kv_store.ephemeral()),
    ];

    let cert_not_after = kv_store
        .load_all_cert_data()
        .into_iter()
        .map(|(domain, data)| (domain, data.not_after))
        .collect();

    Snapshot {
        version: crate::app_version(),
        node_id: kv_store.my_node_id(),
        instances,
        connections: NUM_CONNECTIONS.load(Ordering::Relaxed),
        nodes_total,
        nodes_active,
        accel,
        stores,
        cert_not_after,
    }
}

fn store_snapshot(name: &'static str, node: &wavekv::node::Node) -> StoreSnapshot {
    let status = node.read().status();
    StoreSnapshot {
        name,
        keys: status.n_kvs as u64,
        next_seq: status.next_seq,
        dirty: status.dirty,
        peers: status
            .peers
            .into_iter()
            .map(|peer| PeerSnapshot {
                id: peer.id,
                local_ack: peer.ack,
                peer_ack: peer.pack,
                buffered_logs: peer.logs as u64,
            })
            .collect(),
    }
}
