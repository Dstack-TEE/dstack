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
pub(crate) use tls_terminate::create_acceptor;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{debug, error, info, info_span, Instrument};

use crate::{
    config::ProxyConfig,
    main_service::Proxy,
    models::EnteredCounter,
    pp::{get_inbound_pp_header, DisplayAddr},
};

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
    is_pp: bool,
}

fn parse_app_addr(addr: &str) -> Result<DstInfo> {
    let (app_id, port_part) = addr
        .rsplit_once('-')
        .or_else(|| addr.rsplit_once(':'))
        .unwrap_or((addr, ""));
    if app_id.is_empty() {
        bail!("app id is empty");
    }
    let mut dst = DstInfo {
        app_id: app_id.to_owned(),
        port: 80,
        is_tls: false,
        is_h2: false,
        is_pp: false,
    };

    if port_part.is_empty() {
        return Ok(dst);
    };

    // Parse suffixes from right to left: g, s, p
    let part_bytes = port_part.as_bytes();
    let mut end_idx = part_bytes.len();

    // Parse from right to left until we hit a digit
    while end_idx > 0 {
        let ch = part_bytes[end_idx - 1] as char;
        match ch {
            c if c.is_ascii_digit() => {
                break;
            }
            'g' => {
                if dst.is_h2 {
                    bail!("invalid app address: duplicate suffix 'g'");
                }
                dst.is_h2 = true;
                end_idx -= 1;
            }
            's' => {
                if dst.is_tls {
                    bail!("invalid app address: duplicate suffix 's'");
                }
                dst.is_tls = true;
                end_idx -= 1;
            }
            'p' => {
                if dst.is_pp {
                    bail!("invalid app address: duplicate suffix 'p'");
                }
                dst.is_pp = true;
                end_idx -= 1;
            }
            _ => {
                bail!("invalid app address: unrecognized suffix character '{ch}'");
            }
        }
    }

    if dst.is_h2 && dst.is_tls {
        bail!("invalid app address: both 's' and 'g' suffixes are present");
    }

    let port_str = &port_part[..end_idx];
    let port = if port_str.is_empty() {
        None
    } else {
        Some(port_str.parse::<u16>().context("invalid port")?)
    };
    dst.port = port.unwrap_or(if dst.is_tls { 443 } else { 80 });
    Ok(dst)
}

fn parse_destination(sni: &str, dotted_base_domain: &str) -> Result<DstInfo> {
    // format: <app_id>[-<port>][s].<base_domain>
    let subdomain = sni
        .strip_suffix(dotted_base_domain)
        .context("invalid sni format")?;
    if subdomain.contains('.') {
        bail!("only one level of subdomain is supported, got sni={sni}, subdomain={subdomain}");
    }
    parse_app_addr(subdomain)
}

pub static NUM_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

async fn handle_connection(
    inbound: TcpStream,
    state: Proxy,
    dotted_base_domain: &str,
) -> Result<()> {
    let timeouts = &state.config.proxy.timeouts;

    let pp_timeout = timeouts.pp_header;
    let pp_fut = get_inbound_pp_header(inbound, &state.config.proxy);
    let (mut inbound, pp_header) = timeout(pp_timeout, pp_fut)
        .await
        .context("take proxy protocol header timeout")?
        .context("failed to take proxy protocol header")?;
    info!("client address: {}", DisplayAddr(&pp_header));
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
            tls_passthough::proxy_to_app(state, inbound, pp_header, buffer, &dst).await
        } else {
            state.proxy(inbound, pp_header, buffer, &dst).await
        }
    } else {
        tls_passthough::proxy_with_sni(state, inbound, pp_header, buffer, &sni).await
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
