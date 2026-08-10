// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics for the gateway.
//!
//! Gauges are not stored: they are sampled from live state when a scrape
//! arrives, so a scrape never has to be kept in sync with a mutation.
//!
//! Label values that come from replicated state (domains, and therefore
//! anything a peer can name) are escaped, so a peer cannot forge series in the
//! scrape output.

use std::fmt::Write as _;

use dstack_gateway_rpc::ProxyAccelStatus;

/// Live state sampled for one scrape.
pub(crate) struct Snapshot {
    pub version: String,
    pub node_id: u32,
    pub instances: u64,
    pub connections: u64,
    pub nodes_total: u64,
    pub nodes_active: u64,
    pub accel: ProxyAccelStatus,
    pub stores: Vec<StoreSnapshot>,
    /// domain -> certificate `notAfter`, in seconds since the epoch.
    pub cert_not_after: Vec<(String, u64)>,
}

/// One WaveKV store (`persistent` or `ephemeral`).
pub(crate) struct StoreSnapshot {
    pub name: &'static str,
    pub keys: u64,
    pub next_seq: u64,
    pub dirty: bool,
    pub peers: Vec<PeerSnapshot>,
}

pub(crate) struct PeerSnapshot {
    pub id: u32,
    /// How far we have consumed this peer's log.
    pub local_ack: u64,
    /// How far the peer says it has consumed ours.
    pub peer_ack: u64,
    /// Entries still buffered for the peer. A number that only grows is a peer
    /// that stopped acknowledging.
    pub buffered_logs: u64,
}

/// Render the Prometheus text exposition format.
pub(crate) fn render(snapshot: &Snapshot) -> String {
    let mut out = String::with_capacity(2048);

    gauge(
        &mut out,
        "dstack_gateway_build_info",
        "Gateway build information.",
        &format!(
            "{{version=\"{}\",node_id=\"{}\"}}",
            escape_label(&snapshot.version),
            snapshot.node_id
        ),
        1,
    );
    gauge(
        &mut out,
        "dstack_gateway_instances",
        "CVM instances currently in the routing table.",
        "",
        snapshot.instances,
    );
    gauge(
        &mut out,
        "dstack_gateway_connections",
        "Proxy connections currently open.",
        "",
        snapshot.connections,
    );
    gauge(
        &mut out,
        "dstack_gateway_nodes",
        "Gateway nodes known to this node.",
        "",
        snapshot.nodes_total,
    );
    gauge(
        &mut out,
        "dstack_gateway_nodes_active",
        "Gateway nodes not marked down.",
        "",
        snapshot.nodes_active,
    );

    counter(
        &mut out,
        "dstack_gateway_ktls_offloaded_total",
        "Connections handed to the kernel TLS ULP.",
        "",
        snapshot.accel.ktls_offloaded,
    );
    counter(
        &mut out,
        "dstack_gateway_ktls_offload_failed_total",
        "Connections whose kernel TLS handover failed.",
        "",
        snapshot.accel.ktls_offload_failed,
    );
    counter(
        &mut out,
        "dstack_gateway_splice_engaged_total",
        "Connections that entered a zero-copy splice relay.",
        "",
        snapshot.accel.splice_engaged,
    );

    header(
        &mut out,
        "dstack_gateway_kv_keys",
        "Keys held in a WaveKV store.",
        "gauge",
    );
    for store in &snapshot.stores {
        line(
            &mut out,
            "dstack_gateway_kv_keys",
            &store_label(store),
            store.keys,
        );
    }
    header(
        &mut out,
        "dstack_gateway_kv_next_seq",
        "Next sequence number this node will assign in a WaveKV store.",
        "gauge",
    );
    for store in &snapshot.stores {
        line(
            &mut out,
            "dstack_gateway_kv_next_seq",
            &store_label(store),
            store.next_seq,
        );
    }
    header(
        &mut out,
        "dstack_gateway_kv_dirty",
        "1 when a WaveKV store holds changes that are not in its snapshot.",
        "gauge",
    );
    for store in &snapshot.stores {
        line(
            &mut out,
            "dstack_gateway_kv_dirty",
            &store_label(store),
            u64::from(store.dirty),
        );
    }

    header(
        &mut out,
        "dstack_gateway_kv_peer_local_ack",
        "How far this node has consumed a peer's log.",
        "gauge",
    );
    for (store, peer) in peers(snapshot) {
        line(
            &mut out,
            "dstack_gateway_kv_peer_local_ack",
            &peer_label(store, peer),
            peer.local_ack,
        );
    }
    header(
        &mut out,
        "dstack_gateway_kv_peer_peer_ack",
        "How far a peer reports having consumed this node's log.",
        "gauge",
    );
    for (store, peer) in peers(snapshot) {
        line(
            &mut out,
            "dstack_gateway_kv_peer_peer_ack",
            &peer_label(store, peer),
            peer.peer_ack,
        );
    }
    header(
        &mut out,
        "dstack_gateway_kv_peer_buffered_logs",
        "Log entries still buffered for a peer. Sustained growth means the peer stopped acknowledging.",
        "gauge",
    );
    for (store, peer) in peers(snapshot) {
        line(
            &mut out,
            "dstack_gateway_kv_peer_buffered_logs",
            &peer_label(store, peer),
            peer.buffered_logs,
        );
    }

    header(
        &mut out,
        "dstack_gateway_cert_not_after_seconds",
        "Certificate expiry per domain, in seconds since the epoch.",
        "gauge",
    );
    for (domain, not_after) in &snapshot.cert_not_after {
        line(
            &mut out,
            "dstack_gateway_cert_not_after_seconds",
            &format!("{{domain=\"{}\"}}", escape_label(domain)),
            *not_after,
        );
    }

    out
}

fn peers(snapshot: &Snapshot) -> impl Iterator<Item = (&StoreSnapshot, &PeerSnapshot)> {
    snapshot
        .stores
        .iter()
        .flat_map(|store| store.peers.iter().map(move |peer| (store, peer)))
}

fn store_label(store: &StoreSnapshot) -> String {
    format!("{{store=\"{}\"}}", escape_label(store.name))
}

fn peer_label(store: &StoreSnapshot, peer: &PeerSnapshot) -> String {
    format!(
        "{{store=\"{}\",peer=\"{}\"}}",
        escape_label(store.name),
        peer.id
    )
}

fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn line(out: &mut String, name: &str, labels: &str, value: u64) {
    let _ = writeln!(out, "{name}{labels} {value}");
}

fn gauge(out: &mut String, name: &str, help: &str, labels: &str, value: u64) {
    header(out, name, help, "gauge");
    line(out, name, labels, value);
}

fn counter(out: &mut String, name: &str, help: &str, labels: &str, value: u64) {
    header(out, name, help, "counter");
    line(out, name, labels, value);
}

/// Escape a label value per the exposition format.
///
/// Domains reach this from replicated state, so an unescaped quote or newline
/// would be a peer-controlled way to forge series in the scrape output.
fn escape_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        Snapshot {
            version: "0.0.0-test".to_string(),
            node_id: 7,
            instances: 3,
            connections: 12,
            nodes_total: 3,
            nodes_active: 2,
            accel: ProxyAccelStatus {
                ktls_mode: "off".to_string(),
                splice_mode: "off".to_string(),
                ktls_offloaded: 5,
                ktls_offload_failed: 1,
                splice_engaged: 4,
            },
            stores: vec![StoreSnapshot {
                name: "persistent",
                keys: 42,
                next_seq: 100,
                dirty: true,
                peers: vec![PeerSnapshot {
                    id: 2,
                    local_ack: 9,
                    peer_ack: 8,
                    buffered_logs: 1,
                }],
            }],
            cert_not_after: vec![("app.example.com".to_string(), 1_800_000_000)],
        }
    }

    #[test]
    fn every_series_is_declared_before_it_is_used() {
        let rendered = render(&snapshot());
        let mut declared = std::collections::HashSet::new();
        for row in rendered.lines() {
            if let Some(rest) = row.strip_prefix("# TYPE ") {
                let name = rest.split(' ').next().unwrap_or_default();
                declared.insert(name.to_string());
                continue;
            }
            if row.starts_with('#') {
                continue;
            }
            let name = row
                .split(['{', ' '])
                .next()
                .expect("a sample line names a series");
            assert!(
                declared.contains(name),
                "sample {name} appears without a # TYPE line"
            );
        }
    }

    #[test]
    fn samples_carry_the_values_they_were_given() {
        let rendered = render(&snapshot());
        for expected in [
            "dstack_gateway_build_info{version=\"0.0.0-test\",node_id=\"7\"} 1",
            "dstack_gateway_instances 3",
            "dstack_gateway_connections 12",
            "dstack_gateway_nodes_active 2",
            "dstack_gateway_ktls_offload_failed_total 1",
            "dstack_gateway_kv_keys{store=\"persistent\"} 42",
            "dstack_gateway_kv_dirty{store=\"persistent\"} 1",
            "dstack_gateway_kv_peer_buffered_logs{store=\"persistent\",peer=\"2\"} 1",
            "dstack_gateway_cert_not_after_seconds{domain=\"app.example.com\"} 1800000000",
        ] {
            assert!(rendered.contains(expected), "missing sample: {expected}");
        }
    }

    #[test]
    fn a_hostile_domain_cannot_forge_a_series() {
        let mut snapshot = snapshot();
        // A domain arrives from replicated state, so treat it as peer-supplied.
        snapshot.cert_not_after = vec![(
            "evil\" 1\ndstack_gateway_instances 999\n#".to_string(),
            1_800_000_000,
        )];
        let rendered = render(&snapshot);

        // The injection stays inside one label value on one line: no forged
        // sample line, and the real gauge still reads what it was given.
        let forged = rendered
            .lines()
            .filter(|row| row.starts_with("dstack_gateway_instances "))
            .count();
        assert_eq!(
            forged, 1,
            "the payload escaped its label and became a sample"
        );
        assert!(rendered
            .lines()
            .any(|row| row == "dstack_gateway_instances 3"));
        assert!(rendered.contains(
            "dstack_gateway_cert_not_after_seconds{domain=\"evil\\\" 1\\ndstack_gateway_instances 999\\n#\"} 1800000000"
        ));
    }
}
