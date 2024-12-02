use anyhow::{Context, Result};
use std::fmt::Debug;
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tracing::debug;

use crate::main_service::AppState;
use crate::models::Timeouts;

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
    let resolver = hickory_resolver::AsyncResolver::tokio_from_system_conf()
        .context("failed to create dns resolver")?;
    let lookup = resolver
        .txt_lookup(txt_domain)
        .await
        .context("failed to lookup tapp address")?;
    let txt_record = lookup.iter().next().context("no txt record found")?;
    let data = txt_record
        .txt_data()
        .get(0)
        .context("no data in txt record")?;
    TappAddress::parse(data).context("failed to parse tapp address")
}

pub(crate) async fn proxy_with_sni(
    state: AppState,
    inbound: TcpStream,
    buffer: Vec<u8>,
    sni: &str,
    timeouts: Option<Timeouts>,
) -> Result<()> {
    let tapp_addr = resolve_tapp_address(sni)
        .await
        .context("failed to resolve tapp address")?;
    debug!("target address is {}:{}", tapp_addr.app_id, tapp_addr.port);
    proxy_to_app(state, inbound, buffer, &tapp_addr.app_id, tapp_addr.port, timeouts).await
}

pub(crate) async fn proxy_to_app(
    state: AppState,
    mut inbound: TcpStream,
    buffer: Vec<u8>,
    app_id: &str,
    port: u16,
    timeouts: Option<Timeouts>,
) -> Result<()> {
    let timeouts = timeouts.unwrap_or_default();
    let target_ip = state.lock().select_a_host(app_id).context("tapp not found")?.ip;
    let mut outbound = timeout(
        timeouts.connect,
        TcpStream::connect((target_ip, port))
    )
    .await
    .map_err(|_| anyhow::anyhow!("connection timeout"))?
    .context("failed to connect to tapp")?;
    outbound
        .write_all(&buffer)
        .await
        .context("failed to write to tapp")?;
    let _first_byte_timeout = timeout(
        timeouts.first_byte,
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
    )
    .await
    .map_err(|_| anyhow::anyhow!("first byte timeout"))?
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
