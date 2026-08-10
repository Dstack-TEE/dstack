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

    // Hold the proxy lock only for the counts. The public data path takes it on
    // every connection, so a scrape must not read KV or format anything while
    // holding it.
    let (instances, nodes_total, nodes_active) = {
        let proxy_state = state.lock();
        (
            proxy_state.state.instances.len() as u64,
            proxy_state.get_all_nodes().len() as u64,
            proxy_state.get_active_nodes().len() as u64,
        )
    };

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
