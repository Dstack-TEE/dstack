use anyhow::{Context, Result};
use std::fmt::Debug;
use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinSet, time::timeout};
use tracing::{debug, info};

use crate::main_service::Proxy;

use super::{io_bridge::bridge, AddressGroup};

#[derive(Debug)]
struct TappAddress {
    app_id: String,
    port: u16,
}

impl TappAddress {
    fn parse(data: &[u8]) -> Result<Self> {
        // format: "3327603e03f5bd1f830812ca4a789277fc31f577:555"
        let data = String::from_utf8(data.to_vec()).context("invalid tapp address")?;
        let (app_id, port) = data.split_once(':').context("invalid tapp address")?;
        Ok(Self {
            app_id: app_id.to_string(),
            port: port.parse().context("invalid port")?,
        })
    }
}

/// resolve tapp address by sni
async fn resolve_tapp_address(sni: &str) -> Result<TappAddress> {
    let txt_domain = format!("_tapp-address.{sni}");
    let txt_domain_v2 = format!("_dstack-app-address.{sni}");
    let resolver = hickory_resolver::AsyncResolver::tokio_from_system_conf()
        .context("failed to create dns resolver")?;
    let (lookup, lookup_v2) = tokio::join!(
        resolver.txt_lookup(txt_domain),
        resolver.txt_lookup(txt_domain_v2),
    );
    for lookup in [lookup_v2, lookup] {
        let Ok(lookup) = lookup else {
            continue;
        };
        let Some(txt_record) = lookup.iter().next() else {
            continue;
        };
        let Some(data) = txt_record.txt_data().first() else {
            continue;
        };
        return TappAddress::parse(data).context("failed to parse tapp address");
    }
    anyhow::bail!("failed to resolve tapp address");
}

pub(crate) async fn proxy_with_sni(
    state: Proxy,
    inbound: TcpStream,
    buffer: Vec<u8>,
    sni: &str,
) -> Result<()> {
    let tapp_addr = resolve_tapp_address(sni)
        .await
        .context("failed to resolve tapp address")?;
    debug!("target address is {}:{}", tapp_addr.app_id, tapp_addr.port);
    proxy_to_app(state, inbound, buffer, &tapp_addr.app_id, tapp_addr.port).await
}

/// connect to multiple hosts simultaneously and return the first successful connection
pub(crate) async fn connect_multiple_hosts(
    addresses: AddressGroup,
    port: u16,
) -> Result<TcpStream> {
    let mut join_set = JoinSet::new();
    for addr in addresses {
        debug!("connecting to {addr}:{port}");
        let future = TcpStream::connect((addr, port));
        join_set.spawn(async move { future.await.map_err(|e| (e, addr, port)) });
    }
    // select the first successful connection
    let connection = loop {
        let result = join_set
            .join_next()
            .await
            .context("No connection success")?
            .context("Failed to join the connect task")?;
        match result {
            Ok(connection) => break connection,
            Err((e, addr, port)) => {
                info!("failed to connect to tapp@{addr}:{port}: {e}");
            }
        }
    };
    debug!("connected to {:?}", connection.peer_addr());
    Ok(connection)
}

pub(crate) async fn proxy_to_app(
    state: Proxy,
    inbound: TcpStream,
    buffer: Vec<u8>,
    app_id: &str,
    port: u16,
) -> Result<()> {
    let addresses = state.lock().select_top_n_hosts(app_id)?;
    let mut outbound = timeout(
        state.config.proxy.timeouts.connect,
        connect_multiple_hosts(addresses.clone(), port),
    )
    .await
    .with_context(|| format!("connecting timeout to tapp {app_id}: {addresses:?}:{port}"))?
    .with_context(|| format!("failed to connect to tapp {app_id}: {addresses:?}:{port}"))?;
    outbound
        .write_all(&buffer)
        .await
        .context("failed to write to tapp")?;
    bridge(inbound, outbound, &state.config.proxy)
        .await
        .context("failed to copy between inbound and outbound")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_tapp_address() {
        let tapp_addr =
            resolve_tapp_address("3327603e03f5bd1f830812ca4a789277fc31f577.app.kvin.wang")
                .await
                .unwrap();
        assert_eq!(tapp_addr.app_id, "3327603e03f5bd1f830812ca4a789277fc31f577");
        assert_eq!(tapp_addr.port, 8090);
    }
}
