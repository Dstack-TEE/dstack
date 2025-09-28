// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::fmt::Debug;
use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinSet, time::timeout};
use tracing::{debug, info};

use crate::{
    config::{ForwardingMode, ProxyProtocolVersionConfig},
    main_service::Proxy,
    models::{Counting, EnteredCounter},
};

use super::{
    io_bridge::bridge,
    proxy_protocol::{build_v1_header, build_v2_header, ProxyProtocolVersion},
    AddressGroup, ClientContext,
};

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
    client_context: ClientContext,
) -> Result<()> {
    let ns_prefix = &state.config.proxy.app_address_ns_prefix;
    let compat = state.config.proxy.app_address_ns_compat;
    let addr = resolve_app_address(ns_prefix, sni, compat)
        .await
        .context("failed to resolve app address")?;
    debug!("target address is {}:{}", addr.app_id, addr.port);
    proxy_to_app(state, inbound, buffer, &addr.app_id, addr.port, client_context).await
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

pub(crate) fn prepare_buffer_with_proxy_protocol(
    buffer: &[u8],
    client_context: &ClientContext,
    app_id: &str,
    state: &Proxy,
) -> Vec<u8> {
    // Determine backend forwarding mode
    let pp_config = match &state.config.proxy.proxy_protocol {
        Some(config) if config.enabled => config,
        _ => return buffer.to_vec(), // PROXY Protocol not enabled
    };

    let backend_config = pp_config
        .backend_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(app_id))
        .map(|c| (c.mode.clone(), c.version.clone()))
        .unwrap_or_else(|| {
            (
                pp_config.backend_default.mode.clone(),
                pp_config.backend_default.version.clone(),
            )
        });

    let (mode, version) = backend_config;

    match mode {
        ForwardingMode::Never => {
            // Strip PROXY Protocol header if present
            if let Some(header) = &client_context.proxy_header {
                let header_len = header.raw_header.len();
                if buffer.len() > header_len && buffer.starts_with(&header.raw_header) {
                    buffer[header_len..].to_vec()
                } else {
                    buffer.to_vec()
                }
            } else {
                buffer.to_vec()
            }
        }
        ForwardingMode::Passthrough => {
            // Forward as-is
            buffer.to_vec()
        }
        ForwardingMode::Always => {
            // Always add PROXY Protocol header
            let pp_version = match version {
                Some(ProxyProtocolVersionConfig::V1) => ProxyProtocolVersion::V1,
                Some(ProxyProtocolVersionConfig::V2) | None => ProxyProtocolVersion::V2,
            };

            let header = match pp_version {
                ProxyProtocolVersion::V1 => {
                    build_v1_header(&client_context.real_client, &client_context.direct_peer)
                }
                ProxyProtocolVersion::V2 => {
                    build_v2_header(&client_context.real_client, &client_context.direct_peer)
                }
            };

            // Combine header with data (strip old PP header if present)
            let data_start = if let Some(old_header) = &client_context.proxy_header {
                let header_len = old_header.raw_header.len();
                if buffer.len() > header_len && buffer.starts_with(&old_header.raw_header) {
                    header_len
                } else {
                    0
                }
            } else {
                0
            };

            let mut result = header;
            result.extend_from_slice(&buffer[data_start..]);
            result
        }
        ForwardingMode::Conditional => {
            // Forward if received, otherwise don't add
            if client_context.proxy_header.is_some() {
                buffer.to_vec() // Keep as-is (passthrough)
            } else {
                buffer.to_vec() // No PP header to forward
            }
        }
    }
}

pub(crate) async fn proxy_to_app(
    state: Proxy,
    inbound: TcpStream,
    buffer: Vec<u8>,
    app_id: &str,
    port: u16,
    client_context: ClientContext,
) -> Result<()> {
    let addresses = state.lock().select_top_n_hosts(app_id)?;
    let (mut outbound, _counter) = timeout(
        state.config.proxy.timeouts.connect,
        connect_multiple_hosts(addresses.clone(), port),
    )
    .await
    .with_context(|| format!("connecting timeout to app {app_id}: {addresses:?}:{port}"))?
    .with_context(|| format!("failed to connect to app {app_id}: {addresses:?}:{port}"))?;

    // Prepare buffer with appropriate PROXY Protocol handling
    let buffer_to_send = prepare_buffer_with_proxy_protocol(&buffer, &client_context, app_id, &state);

    outbound
        .write_all(&buffer_to_send)
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
            "3327603e03f5bd1f830812ca4a789277fc31f577.app.kvin.wang",
            false,
        )
        .await
        .unwrap();
        assert_eq!(app_addr.app_id, "3327603e03f5bd1f830812ca4a789277fc31f577");
        assert_eq!(app_addr.port, 8090);
    }
}
