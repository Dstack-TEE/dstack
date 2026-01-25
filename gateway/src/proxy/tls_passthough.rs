// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::fmt::Debug;
use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinSet, time::timeout};
use tracing::{debug, info};

use crate::{
    main_service::Proxy,
    models::{Counting, EnteredCounter},
};

use super::{io_bridge::bridge, AddressGroup};

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

/// resolve app address by sni
async fn resolve_app_address(prefix: &str, sni: &str, compat: bool) -> Result<AppAddress> {
    let txt_domain = format!("{prefix}.{sni}");
    let resolver = hickory_resolver::AsyncResolver::tokio_from_system_conf()
        .context("failed to create dns resolver")?;

    if compat && prefix != "_tapp-address" {
        let txt_domain_legacy = format!("_tapp-address.{sni}");
        let (lookup, lookup_legacy) = tokio::join!(
            resolver.txt_lookup(txt_domain),
            resolver.txt_lookup(txt_domain_legacy),
        );
        for lookup in [lookup, lookup_legacy] {
            let Ok(lookup) = lookup else {
                continue;
            };
            let Some(txt_record) = lookup.iter().next() else {
                continue;
            };
            let Some(data) = txt_record.txt_data().first() else {
                continue;
            };
            return AppAddress::parse(data).context("failed to parse app address");
        }
        anyhow::bail!("failed to resolve app address");
    } else {
        let lookup = resolver
            .txt_lookup(txt_domain)
            .await
            .context("failed to lookup app address")?;
        let txt_record = lookup.iter().next().context("no txt record found")?;
        let data = txt_record
            .txt_data()
            .first()
            .context("no data in txt record")?;
        AppAddress::parse(data).context("failed to parse app address")
    }
}

pub(crate) async fn proxy_with_sni(
    state: Proxy,
    inbound: TcpStream,
    buffer: Vec<u8>,
    sni: &str,
) -> Result<()> {
    let ns_prefix = &state.config.proxy.app_address_ns_prefix;
    let compat = state.config.proxy.app_address_ns_compat;
    let dns_timeout = state.config.proxy.timeouts.dns_resolve;
    let addr = timeout(dns_timeout, resolve_app_address(ns_prefix, sni, compat))
        .await
        .context("DNS TXT resolve timeout")?
        .context("failed to resolve app address")?;
    debug!("target address is {}:{}", addr.app_id, addr.port);
    proxy_to_app(state, inbound, buffer, &addr.app_id, addr.port).await
}

/// connect to multiple hosts simultaneously and return the first successful connection
pub(crate) async fn connect_multiple_hosts(
    addresses: AddressGroup,
    port: u16,
) -> Result<(TcpStream, EnteredCounter)> {
    let mut join_set = JoinSet::new();
    for addr in addresses {
        let counter = addr.counter.enter();
        let addr = addr.ip;
        debug!("connecting to {addr}:{port}");
        let future = TcpStream::connect((addr, port));
        join_set.spawn(async move { (future.await.map_err(|e| (e, addr, port)), counter) });
    }
    // select the first successful connection
    let (connection, counter) = loop {
        let (result, counter) = join_set
            .join_next()
            .await
            .context("No connection success")?
            .context("Failed to join the connect task")?;
        match result {
            Ok(connection) => break (connection, counter),
            Err((e, addr, port)) => {
                info!("failed to connect to app@{addr}:{port}: {e}");
            }
        }
    };
    debug!("connected to {:?}", connection.peer_addr());
    Ok((connection, counter))
}

pub(crate) async fn proxy_to_app(
    state: Proxy,
    inbound: TcpStream,
    buffer: Vec<u8>,
    app_id: &str,
    port: u16,
) -> Result<()> {
    let addresses = state.lock().select_top_n_hosts(app_id)?;
    let (mut outbound, _counter) = timeout(
        state.config.proxy.timeouts.connect,
        connect_multiple_hosts(addresses.clone(), port),
    )
    .await
    .with_context(|| format!("connecting timeout to app {app_id}: {addresses:?}:{port}"))?
    .with_context(|| format!("failed to connect to app {app_id}: {addresses:?}:{port}"))?;
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
        let app_addr = resolve_app_address(
            "_dstack-app-address",
            "3327603e03f5bd1f830812ca4a789277fc31f577.app.dstack.org",
            false,
        )
        .await
        .unwrap();
        assert_eq!(app_addr.app_id, "3327603e03f5bd1f830812ca4a789277fc31f577");
        assert_eq!(app_addr.port, 8090);
    }
}
