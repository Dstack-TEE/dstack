// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use proxy_protocol::ProxyHeader;
use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinSet, time::timeout};
use tracing::{debug, info, warn};

use crate::main_service::Proxy;

use super::{
    io_bridge::bridge_tcp,
    port_policy::{filter_allowed_addresses, should_send_pp},
    AddressGroup,
};

const APP_ADDRESS_DNS_CACHE_SIZE: usize = 256;
const APP_ADDRESS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct AppAddress {
    app_id: String,
    port: u16,
}

impl AppAddress {
    fn parse(data: &[u8]) -> Result<Self> {
        // format: "3327603e03f5bd1f830812ca4a789277fc31f577:555"
        let data = String::from_utf8(data.to_vec()).context("invalid app address")?;
        let (app_id, port) = data.split_once(':').context("invalid app address")?;
        Ok(Self {
            app_id: app_id.to_string(),
            port: port.parse().context("invalid port")?,
        })
    }
}

/// Shared resolver for SNI -> app address TXT lookups.
///
/// Hickory's resolver already has an internal TTL-aware DNS cache. The old
/// code created a new resolver per proxy connection, which defeated that cache.
/// Keeping a resolver in `ProxyInner` makes TXT caching effective across
/// connections without introducing a separate cache invalidation policy here.
pub(crate) struct AppAddressResolver {
    prefix: String,
    compat: bool,
    resolver: TokioResolver,
}

impl AppAddressResolver {
    pub(crate) fn new(prefix: String, compat: bool, dns_servers: Vec<SocketAddr>) -> Result<Self> {
        Ok(Self {
            prefix,
            compat,
            resolver: app_address_tokio_resolver(dns_servers)?,
        })
    }

    async fn resolve(&self, sni: &str) -> Result<AppAddress> {
        resolve_app_address(&self.resolver, &self.prefix, sni, self.compat).await
    }
}

fn app_address_tokio_resolver(dns_servers: Vec<SocketAddr>) -> Result<TokioResolver> {
    let mut builder = if dns_servers.is_empty() {
        TokioResolver::builder_tokio().context("failed to read system dns config")?
    } else {
        let name_servers = dns_servers
            .into_iter()
            .map(|dns_server| {
                let mut name_server = NameServerConfig::udp_and_tcp(dns_server.ip());
                for connection in &mut name_server.connections {
                    connection.port = dns_server.port();
                }
                name_server
            })
            .collect();
        TokioResolver::builder_with_config(
            ResolverConfig::from_parts(None, Vec::new(), name_servers),
            TokioRuntimeProvider::default(),
        )
    };

    // App-address records may appear shortly after a CVM/app is registered.
    // Reusing one resolver enables positive TXT caching, but we do not want a
    // transient NXDOMAIN/NODATA response to hide a newly-added app for too
    // long. Keep positive caching TTL-aware and cap negative caching.
    let options = builder.options_mut();
    options.cache_size = APP_ADDRESS_DNS_CACHE_SIZE as u64;
    options.negative_min_ttl = Some(Duration::ZERO);
    options.negative_max_ttl = Some(APP_ADDRESS_NEGATIVE_CACHE_TTL);

    builder.build().context("failed to build dns resolver")
}

fn parse_lookup(lookup: &Lookup, sni: &str, txt_domain: &str) -> Result<Option<AppAddress>> {
    for answer in lookup.answers() {
        let RData::TXT(txt) = &answer.data else {
            continue;
        };
        let Some(data) = txt.txt_data.first() else {
            continue;
        };
        return AppAddress::parse(data)
            .with_context(|| format!("failed to parse app address for {sni} via {txt_domain}"))
            .map(Some);
    }
    Ok(None)
}

/// Resolve app address by SNI. `resolver` is shared so its DNS cache is reused.
async fn resolve_app_address(
    resolver: &TokioResolver,
    prefix: &str,
    sni: &str,
    compat: bool,
) -> Result<AppAddress> {
    let txt_domain = format!("{prefix}.{sni}");

    if compat && prefix != "_tapp-address" {
        let txt_domain_legacy = format!("_tapp-address.{sni}");
        let (lookup, lookup_legacy) = tokio::join!(
            resolver.txt_lookup(&txt_domain),
            resolver.txt_lookup(&txt_domain_legacy),
        );
        for (lookup, domain) in [
            (lookup, txt_domain.as_str()),
            (lookup_legacy, txt_domain_legacy.as_str()),
        ] {
            let Ok(lookup) = lookup else {
                continue;
            };
            if let Some(app_address) = parse_lookup(&lookup, sni, domain)? {
                return Ok(app_address);
            }
        }
    } else if let Ok(lookup) = resolver.txt_lookup(&txt_domain).await {
        if let Some(app_address) = parse_lookup(&lookup, sni, &txt_domain)? {
            return Ok(app_address);
        }
    }

    // wildcard fallback: try {prefix}-wildcard.{parent_domain}
    if let Some((_, parent)) = sni.split_once('.') {
        let wildcard_domain = format!("{prefix}-wildcard.{parent}");
        let lookup = resolver
            .txt_lookup(&wildcard_domain)
            .await
            .with_context(|| {
                format!("failed to lookup wildcard app address for {sni} via {wildcard_domain}")
            })?;
        return parse_lookup(&lookup, sni, &wildcard_domain)?
            .with_context(|| format!("no txt record found for {sni} via {wildcard_domain}"));
    }

    anyhow::bail!("failed to resolve app address for {sni}");
}

pub(crate) async fn proxy_with_sni(
    state: Proxy,
    inbound: TcpStream,
    pp_header: ProxyHeader,
    buffer: Vec<u8>,
    sni: &str,
) -> Result<()> {
    let dns_timeout = state.config.proxy.timeouts.dns_resolve;
    let addr = timeout(dns_timeout, state.app_address_resolver.resolve(sni))
        .await
        .with_context(|| format!("DNS TXT resolve timeout for {sni}"))?
        .with_context(|| format!("failed to resolve app address for {sni}"))?;
    debug!("target address is {}:{}", addr.app_id, addr.port);
    proxy_to_app(state, inbound, pp_header, buffer, &addr.app_id, addr.port).await
}

/// One of an app's connection slots, given back when the connection ends.
///
/// Not [`EnteredCounter`](crate::models::EnteredCounter): that increments when
/// it is built, and admission has
/// to *be* the increment -- see [`reserve_slot`] -- so the count is already
/// there by the time there is a guard to hold it.
pub(crate) struct ConnectionSlot(Arc<AtomicU64>);

impl ConnectionSlot {
    /// Count a connection that has nothing to be admitted against.
    fn take(counter: &Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter.clone())
    }

    /// Take a slot only if the app stays under `max`, counting `others` --
    /// what the app's remaining instances hold -- against the same limit.
    fn reserve(counter: &Arc<AtomicU64>, others: u64, max: u64) -> Option<Self> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |taken| {
                (taken + others < max).then_some(taken + 1)
            })
            .ok()?;
        Some(Self(counter.clone()))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Admit a connection against the app's limit, taking its slot in the same
/// step.
///
/// The limit used to be a read: the sum of the instances' counters was
/// compared to `max_connections` and only then incremented, by the connect
/// below. Nothing stopped a burst from all reading the same pre-increment
/// total and all passing -- 32 connections arriving together took 20 slots
/// against a limit of 4 -- which is the one regime a connection limit exists
/// for. `fetch_update` makes the decision and the reservation one atomic step,
/// so two connections racing for the last slot are handed different values and
/// only one of them fits.
///
/// `others` is read outside that step, so an app whose *other* instances fill
/// up at the same instant can still overshoot at the boundary: bounded by the
/// number of candidates (`connect_top_n`, 3 by default), not by how many
/// connections arrive together. A single-instance app is exact.
fn reserve_slot(
    counter: &Arc<AtomicU64>,
    others: u64,
    max_connections: u64,
    app_id: &str,
) -> Result<ConnectionSlot> {
    if max_connections == 0 {
        return Ok(ConnectionSlot::take(counter));
    }
    let Some(slot) = ConnectionSlot::reserve(counter, others, max_connections) else {
        let total = counter.load(Ordering::Relaxed) + others;
        warn!(
            app_id,
            total, max_connections, "app connection limit exceeded"
        );
        bail!("app connection limit exceeded: {total}/{max_connections}");
    };
    Ok(slot)
}

/// connect to multiple hosts simultaneously and return the first successful connection
/// along with the instance_id of the winning address.
pub(crate) async fn connect_multiple_hosts(
    addresses: AddressGroup,
    port: u16,
    max_connections: u64,
    app_id: &str,
) -> Result<(TcpStream, ConnectionSlot, String)> {
    let mut candidates = addresses.into_iter();
    let Some(first) = candidates.next() else {
        bail!("no addresses to connect to app <{app_id}>");
    };
    // Admission is counted on the first candidate, which every connection of
    // this app races from too: the slot is the race entry rather than a second
    // count on top of it, and concurrent connections all contend on the same
    // counter.
    let others: u64 = candidates
        .as_slice()
        .iter()
        .map(|addr| addr.counter.load(Ordering::Relaxed))
        .sum();
    let slot = reserve_slot(&first.counter, others, max_connections, app_id)?;

    // Fast path: with a single candidate there is nothing to race, so skip the
    // JoinSet and the task spawn it needs. That allocation and scheduling
    // happened on every connection, and single-address apps are the common
    // case.
    if candidates.as_slice().is_empty() {
        let addr = first;
        let ip = addr.ip;
        debug!("connecting to {ip}:{port}");
        let connection = TcpStream::connect((ip, port))
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to app@{ip}:{port}: {e}"))?;
        let _ = connection.set_nodelay(true);
        return Ok((connection, slot, addr.instance_id));
    }

    let mut join_set = JoinSet::new();
    let mut admitted = Some(slot);
    for addr in std::iter::once(first).chain(candidates) {
        // The admitted slot belongs to the first candidate; the losing racers
        // only need counting, and give their count back when they are dropped.
        let slot = match admitted.take() {
            Some(slot) => slot,
            None => ConnectionSlot::take(&addr.counter),
        };
        let ip = addr.ip;
        let instance_id = addr.instance_id;
        debug!("connecting to {ip}:{port}");
        let future = TcpStream::connect((ip, port));
        join_set.spawn(async move { (future.await.map_err(|e| (e, ip, port)), slot, instance_id) });
    }
    // select the first successful connection
    let (connection, slot, instance_id) = loop {
        let (result, slot, instance_id) = join_set
            .join_next()
            .await
            .context("No connection success")?
            .context("Failed to join the connect task")?;
        match result {
            Ok(connection) => break (connection, slot, instance_id),
            Err((e, addr, port)) => {
                info!("failed to connect to app@{addr}:{port}: {e}");
            }
        }
    };
    // Disable Nagle on the upstream socket for the same reason as the inbound
    // side: avoid delayed-ACK stalls on small proxied messages.
    let _ = connection.set_nodelay(true);
    debug!("connected to {:?}", connection.peer_addr());
    Ok((connection, slot, instance_id))
}

pub(crate) async fn proxy_to_app(
    state: Proxy,
    inbound: TcpStream,
    pp_header: ProxyHeader,
    buffer: Vec<u8>,
    app_id: &str,
    port: u16,
) -> Result<()> {
    let addresses = state.lock().select_top_n_hosts(app_id)?;
    let addresses = filter_allowed_addresses(&state, addresses, app_id, port)?;
    let max_connections = state.config.proxy.max_connections_per_app;
    let (mut outbound, _slot, instance_id) = timeout(
        state.config.proxy.timeouts.connect,
        connect_multiple_hosts(addresses.clone(), port, max_connections, app_id),
    )
    .await
    .with_context(|| format!("connecting timeout to app {app_id}: {addresses:?}:{port}"))?
    .with_context(|| format!("failed to connect to app {app_id}: {addresses:?}:{port}"))?;
    if should_send_pp(&state, &instance_id, port) {
        let pp_header_bin =
            proxy_protocol::encode(pp_header).context("failed to encode pp header")?;
        outbound.write_all(&pp_header_bin).await?;
    }
    outbound
        .write_all(&buffer)
        .await
        .context("failed to write to app")?;
    if let Some(gate) = &state.config.proxy.tcp_splice {
        // Passthrough is a pure TCP relay: move bytes kernel-side with splice.
        // Both ends are plain sockets here, so a FIN is the whole close.
        let idle = state.config.proxy.idle_timeout();
        if gate.engage.is_immediate() {
            super::splice::splice_bidirectional(
                inbound,
                outbound,
                gate.release_idle_pipes,
                idle,
                super::splice::CloseKind::Tcp,
            )
            .await
            .context("failed to splice between inbound and outbound")?;
        } else {
            let buf_size = state.config.proxy.buffer_size;
            super::splice::splice_bidirectional_after(inbound, outbound, gate, buf_size, idle)
                .await
                .context("failed to relay between inbound and outbound")?;
        }
    } else {
        bridge_tcp(inbound, outbound, &state.config.proxy)
            .await
            .context("failed to copy between inbound and outbound")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::AddressInfo;

    /// One instance of an app, the shape `select_top_n_hosts` hands out: every
    /// connection of a burst gets a clone of the same group, so they all count
    /// against the same counter.
    fn one_instance(ip: std::net::Ipv4Addr) -> AddressGroup {
        smallvec::smallvec![AddressInfo {
            ip,
            counter: Arc::new(AtomicU64::new(0)),
            instance_id: "instance".to_string(),
        }]
    }

    /// The check has to *take* the slot. Reading the total and leaving the
    /// increment to the connect below it meant every connection of a burst
    /// observed the same pre-increment total and passed.
    #[test]
    fn a_second_connection_cannot_pass_the_check_the_first_one_won() {
        let group = one_instance(std::net::Ipv4Addr::LOCALHOST);
        let counter = &group[0].counter;
        let _first = reserve_slot(counter, 0, 1, "app").expect("the first connection fits");
        let second = reserve_slot(counter, 0, 1, "app");
        assert!(
            second.is_err(),
            "a connection admitted past a limit of 1 while the first still holds it"
        );
    }

    /// The same thing end to end: connections that arrive together, which is
    /// the only regime the limit exists for.
    ///
    /// One thread per connection released by one barrier, rather than tasks on
    /// a shared runtime: the window between reading the total and taking the
    /// slot is a handful of instructions wide, so connections have to arrive
    /// on different cores at the same instant to be in it at all.
    #[test]
    fn a_burst_of_connections_cannot_overshoot_the_limit() {
        const BURST: usize = 32;
        const MAX: u64 = 4;

        // Never accepted: the kernel's backlog completes the handshakes, which
        // is all a connect needs.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let group = one_instance(std::net::Ipv4Addr::LOCALHOST);
        let barrier = Arc::new(std::sync::Barrier::new(BURST));

        let burst: Vec<_> = (0..BURST)
            .map(|_| {
                let group = group.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    barrier.wait();
                    let connected =
                        rt.block_on(connect_multiple_hosts(group, addr.port(), MAX, "app"));
                    // The slot outlives the socket; the socket does not outlive
                    // its runtime.
                    connected.map(|(stream, slot, _instance)| {
                        drop(stream);
                        slot
                    })
                })
            })
            .collect();

        // Held, so this counts slots taken at the same moment.
        let live: Vec<_> = burst
            .into_iter()
            .filter_map(|thread| thread.join().unwrap().ok())
            .collect();
        assert_eq!(
            live.len(),
            MAX as usize,
            "{BURST} connections arriving together were admitted past a limit of {MAX}"
        );
    }

    #[tokio::test]
    async fn test_resolve_app_address() -> Result<()> {
        let resolver = AppAddressResolver::new("_dstack-app-address".to_string(), false, vec![])?;
        let app_addr = resolver
            .resolve("3327603e03f5bd1f830812ca4a789277fc31f577.app.dstack.org")
            .await?;
        assert_eq!(app_addr.app_id, "3327603e03f5bd1f830812ca4a789277fc31f577");
        assert_eq!(app_addr.port, 8090);
        Ok(())
    }
}
