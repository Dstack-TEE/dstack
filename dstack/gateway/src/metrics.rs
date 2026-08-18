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

use std::cell::Cell;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use dstack_gateway_rpc::ProxyAccelStatus;

use crate::kv::keys;

/// Key prefixes that get their own decode-failure series.
///
/// Taken from `kv::keys` rather than spelled out here: a prefix that is
/// renamed there and not here would not break anything loudly, it would just
/// start counting that key space under `other`.
///
/// Anything unmatched lands in `other`, which is what keeps a peer from
/// inventing key spaces to inflate cardinality.
const METERED_PREFIXES: [&str; 9] = [
    keys::INST_PREFIX,
    keys::NODE_PREFIX,
    keys::CONN_PREFIX,
    keys::HANDSHAKE_PREFIX,
    keys::LAST_SEEN_NODE_PREFIX,
    keys::PEER_ADDR_PREFIX,
    keys::CERT_PREFIX,
    keys::DNS_CRED_PREFIX,
    keys::GLOBAL_PREFIX,
];

const OTHER_PREFIX: &str = "other";

/// Ceiling on `cert_not_after` series, far above any real deployment.
const MAX_CERT_SERIES: usize = 256;

static DECODE_FAILURES: [AtomicU64; METERED_PREFIXES.len() + 1] =
    [const { AtomicU64::new(0) }; METERED_PREFIXES.len() + 1];
static WG_RECONFIGURE_TOTAL: AtomicU64 = AtomicU64::new(0);
static WG_RECONFIGURE_FAILURES: AtomicU64 = AtomicU64::new(0);
static KV_PERSIST_FAILURES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Set while a scrape is sampling live state.
    ///
    /// A scrape reads the same replicated records the data path reads, through
    /// the same decoding helpers, so without this it would feed the very
    /// counter it is about to report: one permanently corrupt record would
    /// increment `decode_failures` once per scrape forever, and `rate()` over
    /// it would measure the scrape interval rather than anything about the
    /// store. Observing must not be indistinguishable from failing.
    static SAMPLING: Cell<bool> = const { Cell::new(false) };
}

/// Suppresses decode-failure counting until dropped.
///
/// Correctness depends on the sampler staying synchronous: it must not yield
/// to the runtime while this is alive, or the flag would apply to whatever
/// else the runtime schedules onto this thread.
pub(crate) struct ScrapeGuard(bool);

impl Drop for ScrapeGuard {
    fn drop(&mut self) {
        SAMPLING.with(|sampling| sampling.set(self.0));
    }
}

/// Mark the current thread as sampling for a scrape. See [`ScrapeGuard`].
#[must_use = "decode-failure suppression ends as soon as the guard is dropped"]
pub(crate) fn scrape_guard() -> ScrapeGuard {
    ScrapeGuard(SAMPLING.with(|sampling| sampling.replace(true)))
}

/// Record that a replicated value could not be decoded.
///
/// A decode failure makes the record invisible to the data plane with nothing
/// but a log line to say so, which is how a single corrupt record turns into
/// "that CVM silently stopped being routable".
///
/// Counting is suppressed while a scrape samples; see [`ScrapeGuard`].
pub(crate) fn record_decode_failure(key: &str) {
    if SAMPLING.with(Cell::get) {
        return;
    }
    DECODE_FAILURES[prefix_index(key)].fetch_add(1, Ordering::Relaxed);
}

/// Record the outcome of pushing a new WireGuard config.
///
/// Covers the whole of `reconfigure()`, not just `wg syncconf`: rendering and
/// writing the config can fail too, and all three leave the data plane on its
/// previous routing table while the gateway keeps answering. `wg syncconf`
/// additionally rejects the *whole* file when one peer stanza is bad, and its
/// call site can only log that, so without a counter a gateway that stopped
/// applying routing updates looks healthy.
pub(crate) fn record_wg_reconfigure(ok: bool) {
    WG_RECONFIGURE_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !ok {
        WG_RECONFIGURE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a failed periodic snapshot. Repeated failures mean the node is one
/// restart away from replaying a very long WAL, or from losing the writes it
/// never managed to snapshot.
pub(crate) fn record_kv_persist_failure() {
    KV_PERSIST_FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// Index of the longest prefix in `prefixes` that `key` starts with.
///
/// Longest rather than first so that adding a narrower prefix later (say
/// `node/status/` next to `node/`) routes keys to the narrower series instead
/// of depending on array order. The current set does not overlap, so this is
/// here to keep the next addition from being a silent mis-bucketing.
fn longest_prefix_index(prefixes: &[&str], key: &str) -> Option<usize> {
    prefixes
        .iter()
        .enumerate()
        .filter(|(_, prefix)| key.starts_with(*prefix))
        .max_by_key(|(_, prefix)| prefix.len())
        .map(|(index, _)| index)
}

fn prefix_index(key: &str) -> usize {
    longest_prefix_index(&METERED_PREFIXES, key).unwrap_or(METERED_PREFIXES.len())
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
    /// Highest sequence from this peer that the local store covers.
    pub local_ack: u64,
    /// Highest local sequence that the peer reports covering.
    pub peer_ack: u64,
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
        "dstack_gateway_cluster_instances",
        "CVM instances currently in the routing table. Replicated: every node reports the same value, so aggregate with max(), not sum().",
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
        "dstack_gateway_cluster_nodes",
        "Gateway nodes known to the cluster. Replicated: aggregate with max(), not sum().",
        "",
        snapshot.nodes_total,
    );
    gauge(
        &mut out,
        "dstack_gateway_cluster_nodes_active",
        "Gateway nodes this node does not consider down. Replicated state seen locally, so disagreement between nodes is itself the replication-lag signal.",
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
        "dstack_gateway_cluster_kv_keys",
        "Keys held in a WaveKV store. Replicated: aggregate with max(), not sum().",
        "gauge",
    );
    for store in &snapshot.stores {
        line(
            &mut out,
            "dstack_gateway_cluster_kv_keys",
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
        "dstack_gateway_kv_peer_remote_ack",
        "How far a peer reports having consumed this node's log.",
        "gauge",
    );
    for (store, peer) in peers(snapshot) {
        line(
            &mut out,
            "dstack_gateway_kv_peer_remote_ack",
            &peer_label(store, peer),
            peer.peer_ack,
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
        "dstack_gateway_wg_reconfigure_total",
        "WireGuard config applications attempted.",
        "",
        WG_RECONFIGURE_TOTAL.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "dstack_gateway_wg_reconfigure_failures_total",
        "WireGuard config applications that did not reach the data plane: render failure, write failure, or a config wg syncconf rejected.",
        "",
        WG_RECONFIGURE_FAILURES.load(Ordering::Relaxed),
    );
    counter(
        &mut out,
        "dstack_gateway_kv_persist_failures_total",
        "Periodic WaveKV snapshots that failed.",
        "",
        KV_PERSIST_FAILURES.load(Ordering::Relaxed),
    );

    gauge(
        &mut out,
        "dstack_gateway_cluster_cert_domains",
        "Domains holding certificate data. Exceeding the number of cert_not_after series means the series were truncated.",
        "",
        snapshot.cert_not_after.len() as u64,
    );
    header(
        &mut out,
        "dstack_gateway_cluster_cert_not_after_seconds",
        "Certificate expiry per domain, in seconds since the epoch. Replicated: every node reports the same series.",
        "gauge",
    );
    // Domains are only created through the admin API, so in practice this is a
    // handful of wildcard certificates. The cap is for the case where it is
    // not: the records are replicated, so a peer with write access could turn
    // one label into an unbounded series count. Truncation is by domain order
    // rather than by expiry so the exported set does not flap between scrapes;
    // `cert_domains` above is what tells you it happened.
    for (domain, not_after) in snapshot.cert_not_after.iter().take(MAX_CERT_SERIES) {
        line(
            &mut out,
            "dstack_gateway_cluster_cert_not_after_seconds",
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
            "dstack_gateway_cluster_instances 3",
            "dstack_gateway_connections 12",
            "dstack_gateway_cluster_nodes_active 2",
            "dstack_gateway_ktls_offload_failed_total 1",
            "dstack_gateway_cluster_kv_keys{store=\"persistent\"} 42",
            "dstack_gateway_kv_dirty{store=\"persistent\"} 1",
            "dstack_gateway_cluster_cert_not_after_seconds{domain=\"app.example.com\"} 1800000000",
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
            "dstack_gateway_cluster_cert_not_after_seconds{domain=\"tabhereandbell\"} 1800000000"
        ));
    }

    #[test]
    fn a_hostile_domain_cannot_forge_a_series() {
        let mut snapshot = snapshot();
        // A domain arrives from replicated state, so treat it as peer-supplied.
        snapshot.cert_not_after = vec![(
            "evil\" 1\ndstack_gateway_cluster_instances 999\n#".to_string(),
            1_800_000_000,
        )];
        let rendered = render(&snapshot);

        // The injection stays inside one label value on one line: no forged
        // sample line, and the real gauge still reads what it was given.
        let forged = rendered
            .lines()
            .filter(|row| row.starts_with("dstack_gateway_cluster_instances "))
            .count();
        assert_eq!(
            forged, 1,
            "the payload escaped its label and became a sample"
        );
        assert!(rendered
            .lines()
            .any(|row| row == "dstack_gateway_cluster_instances 3"));
        assert!(rendered.contains(
            "dstack_gateway_cluster_cert_not_after_seconds{domain=\"evil\\\" 1\\ndstack_gateway_cluster_instances 999\\n#\"} 1800000000"
        ));
    }

    #[test]
    fn decode_failures_are_bucketed_by_key_prefix() {
        assert_eq!(prefix_label(prefix_index("inst/abc")), "inst/");
        // No narrower `node/` prefix is metered, so this folds into `node/`.
        assert_eq!(prefix_label(prefix_index("node/status/3")), "node/");
        assert_eq!(prefix_label(prefix_index("cert/example.com/data")), "cert/");
        assert_eq!(prefix_label(prefix_index("__peer_addr/3")), "__peer_addr/");
        assert_eq!(
            prefix_label(prefix_index("global/certbot_config")),
            "global/"
        );
        // A key a peer invented does not get a series of its own.
        assert_eq!(prefix_label(prefix_index("whatever/1")), "other");
        assert_eq!(prefix_label(prefix_index("")), "other");
    }

    #[test]
    fn a_narrower_prefix_wins_over_a_wider_one() {
        // The metered set does not overlap today, so drive the rule directly:
        // adding `node/status/` later must not depend on where in the array it
        // lands.
        let prefixes = ["node/", "node/status/"];
        assert_eq!(longest_prefix_index(&prefixes, "node/status/3"), Some(1));
        assert_eq!(longest_prefix_index(&prefixes, "node/info/3"), Some(0));

        let reversed = ["node/status/", "node/"];
        assert_eq!(longest_prefix_index(&reversed, "node/status/3"), Some(0));

        assert_eq!(longest_prefix_index(&prefixes, "inst/1"), None);
    }

    #[test]
    fn the_per_domain_expiry_series_is_capped() {
        let mut snapshot = snapshot();
        let total = MAX_CERT_SERIES + 25;
        snapshot.cert_not_after = (0..total)
            .map(|i| (format!("d{i:04}.example.com"), 1_800_000_000 + i as u64))
            .collect();
        let rendered = render(&snapshot);

        let exported = rendered
            .lines()
            .filter(|row| row.starts_with("dstack_gateway_cluster_cert_not_after_seconds{"))
            .count();
        assert_eq!(exported, MAX_CERT_SERIES, "the cap did not hold");
        // The real count still reaches the operator, so truncation is visible
        // rather than silent.
        assert!(rendered
            .lines()
            .any(|row| row == format!("dstack_gateway_cluster_cert_domains {total}")));
    }

    #[test]
    fn a_scrape_does_not_feed_the_counter_it_reports() {
        // Process-wide statics: assert on deltas, never on absolute values.
        let bucket = &DECODE_FAILURES[prefix_index("conn/probe")];
        let before = bucket.load(Ordering::Relaxed);
        {
            let _guard = scrape_guard();
            record_decode_failure("conn/probe");
            // Nested guards must not end suppression early.
            {
                let _inner = scrape_guard();
                record_decode_failure("conn/probe");
            }
            record_decode_failure("conn/probe");
        }
        assert_eq!(
            bucket.load(Ordering::Relaxed),
            before,
            "a scrape counted its own reads"
        );

        record_decode_failure("conn/probe");
        assert_eq!(
            bucket.load(Ordering::Relaxed),
            before + 1,
            "suppression outlived the scrape"
        );
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
