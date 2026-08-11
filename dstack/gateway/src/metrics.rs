// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics for the gateway.
//!
//! Counters live in process-wide atomics rather than on `Proxy` because the
//! sites that need them -- the KV codec, `reconfigure()` -- run on code paths
//! that hold no handle to the proxy state. `proxy::NUM_CONNECTIONS` and
//! `proxy::stats` already work this way.
//!
//! Gauges are not stored: they are sampled from live state when a scrape
//! arrives, so a scrape never has to be kept in sync with a mutation.
//!
//! Label values that come from replicated state (domains, and therefore
//! anything a peer can name) are escaped, and the decode-failure label set is
//! a fixed list of known prefixes plus `other`, so a peer cannot inflate
//! cardinality by inventing keys.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use dstack_gateway_rpc::ProxyAccelStatus;

/// Key prefixes that get their own decode-failure series.
///
/// Longest match wins, so `node/status/` folds into `node/`. Anything unknown
/// is counted under `other`.
const METERED_PREFIXES: [&str; 9] = [
    "inst/",
    "node/",
    "conn/",
    "handshake/",
    "last_seen/",
    "__peer_addr/",
    "cert/",
    "dns_cred/",
    "global/",
];

const OTHER_PREFIX: &str = "other";

static DECODE_FAILURES: [AtomicU64; METERED_PREFIXES.len() + 1] =
    [const { AtomicU64::new(0) }; METERED_PREFIXES.len() + 1];
static WG_SYNCCONF_TOTAL: AtomicU64 = AtomicU64::new(0);
static WG_SYNCCONF_FAILURES: AtomicU64 = AtomicU64::new(0);
static KV_PERSIST_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Record that a replicated value could not be decoded.
///
/// A decode failure makes the record invisible to the data plane with nothing
/// but a log line to say so, which is how a single corrupt record turns into
/// "that CVM silently stopped being routable".
pub(crate) fn record_decode_failure(key: &str) {
    DECODE_FAILURES[prefix_index(key)].fetch_add(1, Ordering::Relaxed);
}

/// Record the outcome of pushing a new WireGuard config.
///
/// `wg syncconf` rejects the *whole* file when one peer stanza is bad, and the
/// call site can only log it, so without a counter a gateway that stopped
/// applying routing updates looks healthy.
pub(crate) fn record_wg_syncconf(ok: bool) {
    WG_SYNCCONF_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !ok {
        WG_SYNCCONF_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a failed periodic snapshot. Repeated failures mean the node is one
/// restart away from replaying a very long WAL, or from losing the writes it
/// never managed to snapshot.
pub(crate) fn record_kv_persist_failure() {
    KV_PERSIST_FAILURES.fetch_add(1, Ordering::Relaxed);
}

fn prefix_index(key: &str) -> usize {
    let mut best: Option<usize> = None;
    for (index, prefix) in METERED_PREFIXES.iter().enumerate() {
        if !key.starts_with(prefix) {
            continue;
        }
        match best {
            Some(current) if METERED_PREFIXES[current].len() >= prefix.len() => {}
            _ => best = Some(index),
        }
    }
    best.unwrap_or(METERED_PREFIXES.len())
}

fn prefix_label(index: usize) -> &'static str {
    METERED_PREFIXES.get(index).copied().unwrap_or(OTHER_PREFIX)
}

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
        "dstack_gateway_kv_decode_failures_total",
        "Replicated values that could not be decoded, by key prefix.",
        "counter",
    );
    for (index, counter) in DECODE_FAILURES.iter().enumerate() {
        line(
            &mut out,
            "dstack_gateway_kv_decode_failures_total",
            &format!("{{prefix=\"{}\"}}", escape_label(prefix_label(index))),
            counter.load(Ordering::Relaxed),
        );
    }

    counter(
        &mut out,
        "dstack_gateway_wg_syncconf_total",
        "WireGuard config applications attempted.",
        "",
        WG_SYNCCONF_TOTAL.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "dstack_gateway_wg_syncconf_failures_total",
        "WireGuard config applications rejected by wg syncconf. A non-zero rate means routing updates are not reaching the data plane.",
        "",
        WG_SYNCCONF_FAILURES.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "dstack_gateway_kv_persist_failures_total",
        "Periodic WaveKV snapshots that failed.",
        "",
        KV_PERSIST_FAILURES.load(Ordering::Relaxed),
    );

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
///
/// The format defines exactly three escapes: `\\`, `\"` and `\n`. Escaping
/// anything else is not the safer choice it looks like -- `prometheus/common`'s
/// parser, which backs `promtool check metrics` and most client tooling,
/// rejects an unknown escape sequence outright. Emitting `\t` would hand the
/// same hostile peer a cheaper attack than the one this function exists to
/// stop: one tab in a domain and the entire scrape stops parsing. Remaining
/// control characters are dropped instead, so the output is valid and carries
/// no raw control bytes either.
fn escape_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ if ch.is_control() => {}
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
    fn only_the_three_escapes_the_format_defines_are_emitted() {
        // The exposition format defines \\, \" and \n and nothing else, and
        // `prometheus/common`'s parser errors on any other escape sequence. A
        // tab that reaches a label value must therefore be dropped rather than
        // written as `\t`, which would cost the whole scrape -- a cheaper
        // attack than the injection this escaping exists to stop.
        assert_eq!(escape_label("a\tb\rc\u{7}d"), "abcd");
        assert_eq!(escape_label("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");

        let mut snapshot = snapshot();
        snapshot.cert_not_after = vec![("tab\there\rand\u{7}bell".to_string(), 1_800_000_000)];
        let rendered = render(&snapshot);
        for undefined in ["\\t", "\\r"] {
            assert!(
                !rendered.contains(undefined),
                "emitted `{undefined}`, an escape the exposition format does not define"
            );
        }
        assert!(rendered.contains(
            "dstack_gateway_cert_not_after_seconds{domain=\"tabhereandbell\"} 1800000000"
        ));
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

    #[test]
    fn decode_failures_are_bucketed_by_longest_matching_prefix() {
        assert_eq!(prefix_label(prefix_index("inst/abc")), "inst/");
        // node/status/ is a sub-prefix of node/: the longer one wins.
        assert_eq!(prefix_label(prefix_index("node/status/3")), "node/");
        assert_eq!(prefix_label(prefix_index("cert/example.com/data")), "cert/");
        assert_eq!(prefix_label(prefix_index("__peer_addr/3")), "__peer_addr/");
        // A key a peer invented does not get a series of its own.
        assert_eq!(prefix_label(prefix_index("whatever/1")), "other");
        assert_eq!(prefix_label(prefix_index("")), "other");
    }

    #[test]
    fn recording_a_failure_moves_its_own_bucket_only() {
        // Process-wide statics: assert on deltas, never on absolute values.
        let before: Vec<u64> = DECODE_FAILURES
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .collect();
        record_decode_failure("dns_cred/abc");
        let after: Vec<u64> = DECODE_FAILURES
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .collect();

        let moved = prefix_index("dns_cred/abc");
        for (index, (before, after)) in before.iter().zip(after.iter()).enumerate() {
            let expected = if index == moved { before + 1 } else { *before };
            assert_eq!(*after, expected, "bucket {} moved unexpectedly", index);
        }
    }
}
