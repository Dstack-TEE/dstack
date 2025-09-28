// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context, Result};
use proxy_protocol::{parse_proxy_protocol, ProxyProtocolHeader};
use sni::extract_sni;
pub(crate) use tls_terminate::create_acceptor;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{debug, error, info, info_span, Instrument};
use trust::TrustStrategy;

use crate::{config::ProxyConfig, main_service::Proxy, models::EnteredCounter};

#[derive(Debug, Clone)]
pub(crate) struct AddressInfo {
    pub ip: Ipv4Addr,
    pub counter: Arc<AtomicU64>,
}

pub(crate) type AddressGroup = smallvec::SmallVec<[AddressInfo; 4]>;

#[derive(Debug, Clone)]
pub struct ClientContext {
    pub direct_peer: SocketAddr,
    pub real_client: SocketAddr,
    pub proxy_header: Option<ProxyProtocolHeader>,
}

mod io_bridge;
mod proxy_protocol;
mod sni;
mod tls_passthough;
mod tls_terminate;
mod trust;

async fn parse_proxy_and_sni(
    stream: &mut TcpStream,
    trust_strategy: Option<&TrustStrategy>,
    direct_peer: SocketAddr,
) -> Result<(ClientContext, Option<String>, Vec<u8>)> {
    let mut buffer = vec![0u8; 8192]; // Increased size for potential PROXY + TLS headers
    let mut data_len = 0;
    let mut proxy_header_len = 0;
    let mut proxy_header: Option<ProxyProtocolHeader> = None;

    // First, try to read and parse PROXY Protocol header if enabled
    if trust_strategy.is_some() {
        // Read initial data that might contain PROXY Protocol
        let n = stream
            .read(&mut buffer[data_len..])
            .await
            .context("failed to read from incoming tcp stream")?;
        if n == 0 {
            bail!("connection closed before data");
        }
        data_len += n;

        // Try to parse PROXY Protocol
        match parse_proxy_protocol(&buffer[..data_len]) {
            Ok(Some(header)) => {
                proxy_header_len = header.raw_header.len();
                proxy_header = Some(header);
                debug!("parsed PROXY Protocol header");
            }
            Ok(None) => {
                debug!("no PROXY Protocol header found");
            }
            Err(e) => {
                // If parsing fails, it might be incomplete, try to read more
                if data_len < 108 {
                    // Max v1 header size
                    let n = stream
                        .read(&mut buffer[data_len..])
                        .await
                        .context("failed to read more data")?;
                    data_len += n;

                    // Try parsing again
                    match parse_proxy_protocol(&buffer[..data_len]) {
                        Ok(Some(header)) => {
                            proxy_header_len = header.raw_header.len();
                            proxy_header = Some(header);
                            debug!("parsed PROXY Protocol header on second attempt");
                        }
                        Ok(None) => {
                            debug!("no PROXY Protocol header after second read");
                        }
                        Err(_) => {
                            debug!("failed to parse PROXY Protocol: {}", e);
                        }
                    }
                } else {
                    debug!("failed to parse PROXY Protocol: {}", e);
                }
            }
        }
    }

    // Determine real client based on PROXY Protocol and trust
    let real_client = if let Some(header) = &proxy_header {
        if let Some(strategy) = trust_strategy {
            if strategy.is_trusted(&direct_peer.ip()) {
                info!("trusted PROXY Protocol from {}", direct_peer);
                header.source
            } else {
                info!("untrusted PROXY Protocol from {}, ignoring", direct_peer);
                direct_peer
            }
        } else {
            direct_peer
        }
    } else {
        direct_peer
    };

    let client_context = ClientContext {
        direct_peer,
        real_client,
        proxy_header: proxy_header.clone(),
    };

    // Now continue reading to extract SNI from the remaining data
    let tls_start = proxy_header_len;

    // Check if we have SNI in the already-read data
    if let Some(sni) = extract_sni(&buffer[tls_start..data_len]) {
        let sni = String::from_utf8(sni.to_vec()).context("sni: invalid utf-8")?;
        debug!("got sni: {sni}");

        // Keep all data including PROXY header for potential forwarding
        buffer.truncate(data_len);
        return Ok((client_context, Some(sni), buffer));
    }

    // Continue reading to get SNI
    loop {
        let n = stream
            .read(&mut buffer[data_len..])
            .await
            .context("failed to read from incoming tcp stream")?;
        if n == 0 {
            break;
        }
        data_len += n;

        if let Some(sni) = extract_sni(&buffer[tls_start..data_len]) {
            let sni = String::from_utf8(sni.to_vec()).context("sni: invalid utf-8")?;
            debug!("got sni: {sni}");
            buffer.truncate(data_len);
            return Ok((client_context, Some(sni), buffer));
        }
    }

    buffer.truncate(data_len);
    Ok((client_context, None, buffer))
}

fn is_subdomain(sni: &str, base_domain: &str) -> bool {
    sni.ends_with(base_domain)
}

#[derive(Debug)]
struct DstInfo {
    app_id: String,
    port: u16,
    is_tls: bool,
    is_h2: bool,
}

fn parse_destination(sni: &str, dotted_base_domain: &str) -> Result<DstInfo> {
    // format: <app_id>[-<port>][s].<base_domain>
    let subdomain = sni
        .strip_suffix(dotted_base_domain)
        .context("invalid sni format")?;
    if subdomain.contains('.') {
        bail!("only one level of subdomain is supported, got sni={sni}, subdomain={subdomain}");
    }
    let mut parts = subdomain.split('-');
    let app_id = parts.next().context("no app id found")?.to_owned();
    if app_id.is_empty() {
        bail!("app id is empty");
    }
    let last_part = parts.next();
    let is_tls;
    let port;
    let is_h2;
    match last_part {
        None => {
            is_tls = false;
            is_h2 = false;
            port = None;
        }
        Some(last_part) => {
            let (port_str, has_g) = match last_part.strip_suffix('g') {
                Some(without_g) => (without_g, true),
                None => (last_part, false),
            };

            let (port_str, has_s) = match port_str.strip_suffix('s') {
                Some(without_s) => (without_s, true),
                None => (port_str, false),
            };
            if has_g && has_s {
                bail!("invalid sni format: `gs` is not allowed");
            }
            is_h2 = has_g;
            is_tls = has_s;
            port = if port_str.is_empty() {
                None
            } else {
                Some(port_str.parse::<u16>().context("invalid port")?)
            };
        }
    };
    let port = port.unwrap_or(if is_tls { 443 } else { 80 });
    if parts.next().is_some() {
        bail!("invalid sni format");
    }
    Ok(DstInfo {
        app_id,
        port,
        is_tls,
        is_h2,
    })
}

pub static NUM_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

async fn handle_connection(
    mut inbound: TcpStream,
    state: Proxy,
    dotted_base_domain: &str,
    direct_peer: SocketAddr,
) -> Result<()> {
    let timeouts = &state.config.proxy.timeouts;

    // Prepare trust strategy if PROXY Protocol is enabled
    let trust_strategy = if let Some(pp_config) = &state.config.proxy.proxy_protocol {
        if pp_config.enabled {
            Some(TrustStrategy::from_config(&pp_config.trust_strategy)?)
        } else {
            None
        }
    } else {
        None
    };

    let (client_context, sni, buffer) = timeout(
        timeouts.handshake,
        parse_proxy_and_sni(&mut inbound, trust_strategy.as_ref(), direct_peer),
    )
    .await
    .context("parse proxy and sni timeout")?
    .context("failed to parse proxy and sni")?;

    info!(
        "connection from {} (real: {})",
        client_context.direct_peer, client_context.real_client
    );

    let Some(sni) = sni else {
        bail!("no sni found");
    };

    if is_subdomain(&sni, dotted_base_domain) {
        let dst = parse_destination(&sni, dotted_base_domain)?;
        debug!("dst: {dst:?}");
        if dst.is_tls {
            tls_passthough::proxy_to_app(
                state,
                inbound,
                buffer,
                &dst.app_id,
                dst.port,
                client_context,
            )
            .await
        } else {
            state
                .proxy_with_context(
                    inbound,
                    buffer,
                    &dst.app_id,
                    dst.port,
                    dst.is_h2,
                    client_context,
                )
                .await
        }
    } else {
        tls_passthough::proxy_with_sni(state, inbound, buffer, &sni, client_context).await
    }
}

#[inline(never)]
pub async fn proxy_main(config: &ProxyConfig, proxy: Proxy) -> Result<()> {
    let workers_rt = tokio::runtime::Builder::new_multi_thread()
        .thread_name("proxy-worker")
        .enable_all()
        .worker_threads(config.workers)
        .build()
        .expect("Failed to build Tokio runtime");

    let dotted_base_domain = {
        let base_domain = config.base_domain.as_str();
        let base_domain = base_domain.strip_prefix(".").unwrap_or(base_domain);
        Arc::new(format!(".{base_domain}"))
    };
    let listener = TcpListener::bind((config.listen_addr, config.listen_port))
        .await
        .with_context(|| {
            format!(
                "failed to bind {}:{}",
                config.listen_addr, config.listen_port
            )
        })?;
    info!(
        "tcp bridge listening on {}:{}",
        config.listen_addr, config.listen_port
    );

    loop {
        match listener.accept().await {
            Ok((inbound, from)) => {
                let span = info_span!("conn", id = next_connection_id());
                let _enter = span.enter();
                let conn_entered = EnteredCounter::new(&NUM_CONNECTIONS);

                info!(%from, "new connection");
                let proxy = proxy.clone();
                let dotted_base_domain = dotted_base_domain.clone();
                workers_rt.spawn(
                    async move {
                        let _conn_entered = conn_entered;
                        let timeouts = &proxy.config.proxy.timeouts;
                        let result = timeout(
                            timeouts.total,
                            handle_connection(inbound, proxy, &dotted_base_domain, from),
                        )
                        .await;
                        match result {
                            Ok(Ok(_)) => {
                                info!("connection closed");
                            }
                            Ok(Err(e)) => {
                                error!("connection error: {e:?}");
                            }
                            Err(_) => {
                                error!("connection kept too long, force closing");
                            }
                        }
                    }
                    .in_current_span(),
                );
            }
            Err(e) => {
                error!("failed to accept connection: {e:?}");
            }
        }
    }
}

fn next_connection_id() -> usize {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub fn start(config: ProxyConfig, app_state: Proxy) {
    std::thread::Builder::new()
        .name("proxy-main".to_string())
        .spawn(move || {
            // Create a new single-threaded runtime
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");

            // Run the proxy_main function in this runtime
            if let Err(err) = rt.block_on(proxy_main(&config, app_state)) {
                error!(
                    "error on {}:{}: {err:?}",
                    config.listen_addr, config.listen_port
                );
            }
        })
        .expect("Failed to spawn proxy-main thread");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_destination() {
        let base_domain = ".example.com";

        // Test basic app_id only
        let result = parse_destination("myapp.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 80);
        assert!(!result.is_tls);

        // Test app_id with custom port
        let result = parse_destination("myapp-8080.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 8080);
        assert!(!result.is_tls);

        // Test app_id with TLS
        let result = parse_destination("myapp-443s.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 443);
        assert!(result.is_tls);

        // Test app_id with custom port and TLS
        let result = parse_destination("myapp-8443s.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 8443);
        assert!(result.is_tls);

        // Test default port but ends with s
        let result = parse_destination("myapps.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapps");
        assert_eq!(result.port, 80);
        assert!(!result.is_tls);

        // Test default port but ends with s in port part
        let result = parse_destination("myapp-s.example.com", base_domain).unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 443);
        assert!(result.is_tls);
    }

    #[test]
    fn test_parse_destination_errors() {
        let base_domain = ".example.com";

        // Test invalid domain suffix
        assert!(parse_destination("myapp.wrong.com", base_domain).is_err());

        // Test multiple subdomains
        assert!(parse_destination("invalid.myapp.example.com", base_domain).is_err());

        // Test invalid port format
        assert!(parse_destination("myapp-65536.example.com", base_domain).is_err());
        assert!(parse_destination("myapp-abc.example.com", base_domain).is_err());

        // Test too many parts
        assert!(parse_destination("myapp-8080-extra.example.com", base_domain).is_err());

        // Test empty app_id
        assert!(parse_destination("-8080.example.com", base_domain).is_err());
        assert!(parse_destination("myapp-8080ss.example.com", base_domain).is_err());
    }
}
