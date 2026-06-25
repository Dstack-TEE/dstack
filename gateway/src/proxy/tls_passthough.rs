// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hickory_resolver::{lookup::TxtLookup, TokioAsyncResolver};
use proxy_protocol::ProxyHeader;
use tokio::sync::OnceCell;
use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinSet, time::timeout};
use tracing::{debug, info, warn};

use crate::{
    main_service::Proxy,
    models::{Counting, EnteredCounter},
};

use super::{
    io_bridge::bridge,
    port_policy::{filter_allowed_addresses, should_send_pp},
    AddressGroup,
};

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
    resolver: OnceCell<TokioAsyncResolver>,
}

impl AppAddressResolver {
    pub(crate) fn new(prefix: String, compat: bool) -> Self {
        Self {
            prefix,
            compat,
            resolver: OnceCell::new(),
        }
    }

    async fn resolver(&self) -> Result<&TokioAsyncResolver> {
        self.resolver
            .get_or_try_init(|| async { app_address_tokio_resolver_from_system_conf() })
            .await
    }

    async fn resolve(&self, sni: &str) -> Result<AppAddress> {
        resolve_app_address(self.resolver().await?, &self.prefix, sni, self.compat).await
    }
}

fn app_address_tokio_resolver_from_system_conf() -> Result<TokioAsyncResolver> {
    let (config, mut options) = hickory_resolver::system_conf::read_system_conf()
        .context("failed to read system dns config")?;

    // App-address records may appear shortly after a CVM/app is registered.
    // Reusing one resolver enables positive TXT caching, but we do not want a
    // transient NXDOMAIN/NODATA response to hide a newly-added app for too
    // long. Keep positive caching TTL-aware and cap negative caching.
    options.negative_min_ttl = Some(Duration::ZERO);
    options.negative_max_ttl = Some(APP_ADDRESS_NEGATIVE_CACHE_TTL);

    Ok(TokioAsyncResolver::tokio(config, options))
}

fn parse_lookup(lookup: &TxtLookup, sni: &str, txt_domain: &str) -> Result<Option<AppAddress>> {
    let Some(txt_record) = lookup.iter().next() else {
        return Ok(None);
    };
    let Some(data) = txt_record.txt_data().first() else {
        return Ok(None);
    };
    AppAddress::parse(data)
        .with_context(|| format!("failed to parse app address for {sni} via {txt_domain}"))
        .map(Some)
}

/// Resolve app address by SNI. `resolver` is shared so its DNS cache is reused.
async fn resolve_app_address(
    resolver: &TokioAsyncResolver,
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

/// Check if app has reached max connections limit
fn check_connection_limit(
    addresses: &AddressGroup,
    max_connections: u64,
    app_id: &str,
) -> Result<()> {
    if max_connections == 0 {
        return Ok(());
    }
    let total: u64 = addresses
        .iter()
        .map(|a| a.counter.load(Ordering::Relaxed))
        .sum();
    if total >= max_connections {
        warn!(
            app_id,
            total, max_connections, "app connection limit exceeded"
        );
        bail!("app connection limit exceeded: {total}/{max_connections}");
    }
    Ok(())
}

/// connect to multiple hosts simultaneously and return the first successful connection
/// along with the instance_id of the winning address.
pub(crate) async fn connect_multiple_hosts(
    addresses: AddressGroup,
    port: u16,
    max_connections: u64,
    app_id: &str,
) -> Result<(TcpStream, EnteredCounter, String)> {
    check_connection_limit(&addresses, max_connections, app_id)?;

    let mut join_set = JoinSet::new();
    for addr in addresses {
        let counter = addr.counter.enter();
        let ip = addr.ip;
        let instance_id = addr.instance_id;
        debug!("connecting to {ip}:{port}");
        let future = TcpStream::connect((ip, port));
        join_set.spawn(async move {
            (
                future.await.map_err(|e| (e, ip, port)),
                counter,
                instance_id,
            )
        });
    }
    // select the first successful connection
    let (connection, counter, instance_id) = loop {
        let (result, counter, instance_id) = join_set
            .join_next()
            .await
            .context("No connection success")?
            .context("Failed to join the connect task")?;
        match result {
            Ok(connection) => break (connection, counter, instance_id),
            Err((e, addr, port)) => {
                info!("failed to connect to app@{addr}:{port}: {e}");
            }
        }
    };
    debug!("connected to {:?}", connection.peer_addr());
    Ok((connection, counter, instance_id))
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
    let (mut outbound, _counter, instance_id) = timeout(
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
    bridge(inbound, outbound, &state.config.proxy)
        .await
        .context("failed to copy between inbound and outbound")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_app_address() {
        let resolver = AppAddressResolver::new("_dstack-app-address".to_string(), false);
        let app_addr = resolver
            .resolve("3327603e03f5bd1f830812ca4a789277fc31f577.app.dstack.org")
            .await
            .unwrap();
        assert_eq!(app_addr.app_id, "3327603e03f5bd1f830812ca4a789277fc31f577");
        assert_eq!(app_addr.port, 8090);
    }
}
