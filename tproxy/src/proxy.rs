use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use sni::extract_sni;
use tls_terminate::TlsTerminateProxy;
use tokio::{
    io::AsyncReadExt as _,
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info};

use crate::{config::ProxyConfig, main_service::AppState};
use crate::models::Timeouts;

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

struct DstInfo {
    app_id: String,
    port: Option<u16>,
    is_tls: bool,
}

fn parse_destination(sni: &str, dotted_base_domain: &str) -> Result<DstInfo> {
    // format: <app_id>[-<port>][s].<base_domain>
    let subdomain = sni
        .strip_suffix(dotted_base_domain)
        .context("invalid sni format")?;
    if subdomain.contains('.') {
        bail!("only one level of subdomain is supported");
    }
    let is_tls;
    let subdomain = match subdomain.strip_suffix("s") {
        None => {
            is_tls = false;
            subdomain
        }
        Some(subdomain) => {
            is_tls = true;
            subdomain
        }
    };
    let mut parts = subdomain.split('-');
    let app_id = parts.next().context("no app id found")?.to_owned();
    let port = parts
        .next()
        .map(|p| p.parse().context("invalid port"))
        .transpose()?;
    if parts.next().is_some() {
        bail!("invalid sni format");
    }
    Ok(DstInfo {
        app_id,
        port,
        is_tls,
    })
}

async fn handle_connection(
    mut inbound: TcpStream,
    state: AppState,
    dotted_base_domain: &str,
    tls_terminate_proxy: Arc<TlsTerminateProxy>,
    timeouts: Option<Timeouts>,
) -> Result<()> {
    let (sni, buffer) = take_sni(&mut inbound).await.context("failed to take sni")?;
    let Some(sni) = sni else {
        bail!("no sni found");
    };
    if is_subdomain(&sni, dotted_base_domain) {
        let dst = parse_destination(&sni, dotted_base_domain)?;
        if dst.is_tls {
            tls_passthough::proxy_to_app(
                state,
                inbound,
                buffer,
                &dst.app_id,
                dst.port.unwrap_or(443),
                timeouts,
            )
            .await
            .with_context(|| format!("error on connection {sni}"))
        } else {
            tls_terminate_proxy
                .proxy(inbound, buffer, &dst.app_id, dst.port, timeouts)
                .await
                .with_context(|| format!("error on connection {sni}"))
        }
    } else {
        tls_passthough::proxy_with_sni(state, inbound, buffer, &sni, timeouts)
            .await
            .with_context(|| format!("error on connection {sni}"))
    }
}

pub async fn run(config: &ProxyConfig, app_state: AppState) -> Result<()> {
    let dotted_base_domain = {
        let base_domain = config.base_domain.as_str();
        let base_domain = base_domain.strip_prefix(".").unwrap_or(base_domain);
        Arc::new(format!(".{base_domain}"))
    };
    let timeouts = Timeouts {
        connect: Duration::from_secs(config.connect_timeout.into()),
        first_byte: Duration::from_secs(config.first_byte_timeout.into()),
    };

    let tls_terminate_proxy =
        TlsTerminateProxy::new(&app_state, &config.cert_chain, &config.cert_key)
            .context("failed to create tls terminate proxy")?;
    let tls_terminate_proxy = Arc::new(tls_terminate_proxy);

    let listener = TcpListener::bind((config.listen_addr.clone(), config.listen_port))
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
            Ok((inbound, addr)) => {
                info!("new connection from {addr}");
                let app_state = app_state.clone();
                let dotted_base_domain = dotted_base_domain.clone();
                let tls_terminate_proxy = tls_terminate_proxy.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(
                        inbound,
                        app_state,
                        &dotted_base_domain,
                        tls_terminate_proxy,
                        Some(timeouts),
                    )
                    .await
                    {
                        error!("failed to handle connection: {e:?}");
                    }
                });
            }
            Err(e) => {
                error!("failed to accept connection: {e:?}");
            }
        }
    }
}

pub fn start(config: ProxyConfig, app_state: AppState) {
    tokio::spawn(async move {
        if let Err(err) = run(&config, app_state).await {
            error!(
                "error on {}:{}: {err:?}",
                config.listen_addr, config.listen_port
            );
        }
    });
}
