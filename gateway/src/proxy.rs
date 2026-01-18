// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context, Result};
use sni::extract_sni;
pub(crate) use tls_terminate::{create_acceptor, create_acceptor_with_cert_store};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    time::timeout,
};
use tracing::{debug, error, info, info_span, Instrument};

use crate::{config::ProxyConfig, main_service::Proxy, models::EnteredCounter};

#[derive(Debug, Clone)]
pub(crate) struct AddressInfo {
    pub ip: Ipv4Addr,
    pub counter: Arc<AtomicU64>,
}

pub(crate) type AddressGroup = smallvec::SmallVec<[AddressInfo; 4]>;

mod io_bridge;
mod sni;
mod tls_passthough;
mod tls_terminate;

async fn take_sni(stream: &mut TcpStream) -> Result<(Option<String>, Vec<u8>)> {
    let mut buffer = vec![0u8; 4096];
    let mut data_len = 0;
    loop {
        // read data from stream
        let n = stream
            .read(&mut buffer[data_len..])
            .await
            .context("failed to read from incoming tcp stream")?;
        if n == 0 {
            break;
        }
        data_len += n;

        if let Some(sni) = extract_sni(&buffer[..data_len]) {
            let sni = String::from_utf8(sni.to_vec()).context("sni: invalid utf-8")?;
            debug!("got sni: {sni}");
            buffer.truncate(data_len);
            return Ok((Some(sni), buffer));
        }
    }
    buffer.truncate(data_len);
    Ok((None, buffer))
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
) -> Result<()> {
    let timeouts = &state.config.proxy.timeouts;
    let (sni, buffer) = timeout(timeouts.handshake, take_sni(&mut inbound))
        .await
        .context("take sni timeout")?
        .context("failed to take sni")?;
    let Some(sni) = sni else {
        bail!("no sni found");
    };
    if is_subdomain(&sni, dotted_base_domain) {
        let dst = parse_destination(&sni, dotted_base_domain)?;
        debug!("dst: {dst:?}");
        if dst.is_tls {
            tls_passthough::proxy_to_app(state, inbound, buffer, &dst.app_id, dst.port).await
        } else {
            state
                .proxy(inbound, buffer, &dst.app_id, dst.port, dst.is_h2)
                .await
        }
    } else if state.cert_store.has_cert_for_sni(&sni) {
        // SNI matches a managed certificate (e.g., wildcard cert for *.test0.local)
        // Handle as TLS termination with health check endpoint
        debug!(
            sni,
            "SNI matches managed certificate, serving health endpoint"
        );
        state.handle_managed_cert_domain(inbound, buffer).await
    } else {
        tls_passthough::proxy_with_sni(state, inbound, buffer, &sni).await
    }
}

#[inline(never)]
pub async fn proxy_main(rt: &Runtime, config: &ProxyConfig, proxy: Proxy) -> Result<()> {
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
                rt.spawn(
                    async move {
                        let _conn_entered = conn_entered;
                        let timeouts = &proxy.config.proxy.timeouts;
                        let result = timeout(
                            timeouts.total,
                            handle_connection(inbound, proxy, &dotted_base_domain),
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

pub fn start(config: ProxyConfig, app_state: Proxy) -> Result<()> {
    std::thread::Builder::new()
        .name("proxy-main".to_string())
        .spawn(move || {
            // Create a new single-threaded runtime
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");

            let worker_rt = tokio::runtime::Builder::new_multi_thread()
                .thread_name("proxy-worker")
                .enable_all()
                .worker_threads(config.workers)
                .build()
                .expect("Failed to build Tokio runtime");

            // Run the proxy_main function in this runtime
            if let Err(err) = rt.block_on(proxy_main(&worker_rt, &config, app_state)) {
                error!(
                    "error on {}:{}: {err:?}",
                    config.listen_addr, config.listen_port
                );
            }
        })
        .context("Failed to spawn proxy-main thread")?;
    Ok(())
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
