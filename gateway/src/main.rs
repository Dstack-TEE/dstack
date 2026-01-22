// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::{Config, TlsConfig};
use dstack_guest_agent_rpc::{dstack_guest_client::DstackGuestClient, GetTlsKeyArgs};
use http_client::prpc::PrpcClient;
use ra_rpc::{client::RaClient, prpc_routes as prpc, rocket_helper::QuoteVerifier};
use rocket::{
    fairing::AdHoc,
    figment::{providers::Serialized, Figment},
};
use tracing::info;

use admin_service::AdminRpcHandler;
use main_service::{Proxy, ProxyOptions, RpcHandler};

use crate::debug_service::DebugRpcHandler;

mod admin_service;
mod cert_store;
mod config;
mod debug_service;
mod distributed_certbot;
mod kv;
mod main_service;
mod models;
mod proxy;
mod web_routes;

#[global_allocator]
static ALLOCATOR: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn app_version() -> String {
    const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
    const VERSION: &str = git_version::git_version!(
        args = ["--abbrev=20", "--always", "--dirty=-modified"],
        prefix = "git:",
        fallback = "unknown"
    );
    format!("v{CARGO_PKG_VERSION} ({VERSION})")
}

#[derive(Parser)]
#[command(author, version, about, long_version = app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

#[cfg(unix)]
fn set_max_ulimit() -> Result<()> {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE)?;
    if soft < hard {
        setrlimit(Resource::RLIMIT_NOFILE, hard, hard)?;
    }
    Ok(())
}

fn dstack_agent() -> Result<DstackGuestClient<PrpcClient>> {
    let address = dstack_types::dstack_agent_address();
    let http_client = PrpcClient::new(address);
    Ok(DstackGuestClient::new(http_client))
}

async fn maybe_gen_certs(config: &Config, tls_config: &TlsConfig) -> Result<()> {
    if config.rpc_domain.is_empty() {
        info!("TLS domain is empty, skipping cert generation");
        return Ok(());
    }

    // Build alt_names: include rpc_domain and hostname from my_url
    let mut alt_names = vec![config.rpc_domain.clone()];
    if let Ok(url) = reqwest::Url::parse(&config.sync.my_url) {
        if let Some(host) = url.host_str() {
            if host != config.rpc_domain {
                alt_names.push(host.to_string());
            }
        }
    }
    match config.debug.insecure_skip_attestation {
        true => gen_debug_certs(config, tls_config, alt_names).await,
        false => gen_prod_certs(tls_config, alt_names).await,
    }
}

async fn gen_prod_certs(tls_config: &TlsConfig, alt_names: Vec<String>) -> Result<()> {
    info!("Using dstack guest agent for certificate generation");
    let agent_client = dstack_agent().context("Failed to create dstack client")?;

    let response = agent_client
        .get_tls_key(GetTlsKeyArgs {
            subject: "dstack-gateway".to_string(),
            alt_names,
            usage_ra_tls: true,
            usage_server_auth: true,
            usage_client_auth: true,
            not_before: None,
            not_after: None,
        })
        .await?;

    let ca_cert = response
        .certificate_chain
        .last()
        .context("Empty certificate chain")?
        .to_string();
    let certs = response.certificate_chain.join("\n");
    write_cert(&tls_config.mutual.ca_certs, &ca_cert)?;
    write_cert(&tls_config.certs, &certs)?;
    write_cert(&tls_config.key, &response.key)?;
    Ok(())
}

async fn gen_debug_certs(
    config: &Config,
    tls_config: &TlsConfig,
    alt_names: Vec<String>,
) -> Result<()> {
    let kms_url = config.kms_url.clone();
    if kms_url.is_empty() {
        info!("KMS URL is empty, skipping cert generation");
        return Ok(());
    }
    let kms_url = format!("{kms_url}/prpc");
    info!("Getting temp CA cert from {kms_url}");
    let client = RaClient::new(kms_url, true).context("Failed to create kms client")?;
    let client = dstack_kms_rpc::kms_client::KmsClient::new(client);
    let temp_ca_response = client.get_temp_ca_cert().await?;
    let ca_cert = temp_ca_response.temp_ca_cert.clone();
    let temp_ca =
        ra_tls::cert::CaCert::new(temp_ca_response.temp_ca_cert, temp_ca_response.temp_ca_key)
            .context("Failed to create temp CA")?;
    let key = ra_tls::rcgen::KeyPair::generate().context("Failed to generate key")?;
    let cert_req = ra_tls::cert::CertRequest::builder()
        .key(&key)
        .subject("dstack-gateway")
        .alt_names(&alt_names)
        .usage_server_auth(true)
        .usage_client_auth(true)
        .build();
    let cert = temp_ca
        .sign(cert_req)
        .context("Failed to sign rpc cert with temp CA")?;

    write_cert(&tls_config.mutual.ca_certs, &ca_cert)?;
    write_cert(&tls_config.certs, &cert.pem())?;
    write_cert(&tls_config.key, &key.serialize_pem())?;
    Ok(())
}

fn write_cert(path: &str, cert: &str) -> Result<()> {
    info!("Writing cert to file: {path}");
    safe_write::safe_write(path, cert)?;
    Ok(())
}

#[rocket::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());

    let config = figment.focus("core").extract::<Config>()?;

    // Validate node_id
    if config.sync.enabled && config.sync.node_id == 0 {
        anyhow::bail!("node_id must be greater than 0");
    }

    config::setup_wireguard(&config.wg)?;

    let tls_config = figment
        .focus("tls")
        .extract::<TlsConfig>()
        .context("Failed to extract tls config")?;
    maybe_gen_certs(&config, &tls_config)
        .await
        .context("Failed to generate certs")?;

    #[cfg(unix)]
    if config.set_ulimit {
        set_max_ulimit()?;
    }

    let my_app_id = if config.debug.insecure_skip_attestation {
        None
    } else {
        let dstack_client = dstack_agent().context("Failed to create dstack client")?;
        let info = dstack_client
            .info()
            .await
            .context("Failed to get app info")?;
        Some(info.app_id)
    };
    let proxy_config = config.proxy.clone();
    let pccs_url = config.pccs_url.clone();
    let admin_enabled = config.admin.enabled;
    let debug_config = config.debug.clone();
    let state = Proxy::new(ProxyOptions {
        config,
        my_app_id,
        tls_config,
    })
    .await?;
    info!("Starting background tasks");
    state.start_bg_tasks().await?;
    state.lock().reconfigure()?;

    proxy::start(proxy_config, state.clone()).context("failed to start the proxy")?;

    let admin_value = figment
        .find_value("core.admin")
        .context("admin section not found")?;
    let debug_value = figment
        .find_value("core.debug")
        .context("debug section not found")?;

    let admin_figment = Figment::new()
        .merge(rocket::Config::default())
        .merge(Serialized::defaults(admin_value));

    let debug_figment = Figment::new()
        .merge(rocket::Config::default())
        .merge(Serialized::defaults(debug_value));

    let mut rocket = rocket::custom(figment)
        .mount("/prpc", prpc!(Proxy, RpcHandler, trim: "Tproxy."))
        // Mount WaveKV sync endpoint (requires mTLS gateway auth)
        .mount("/", web_routes::wavekv_sync_routes())
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .manage(state.clone());
    let verifier = QuoteVerifier::new(pccs_url);
    rocket = rocket.manage(verifier);
    let main_srv = rocket.launch();
    let admin_state = state.clone();
    let debug_state = state;
    let admin_srv = async move {
        if admin_enabled {
            rocket::custom(admin_figment)
                .mount("/", web_routes::routes())
                .mount("/", prpc!(Proxy, AdminRpcHandler, trim: "Admin."))
                .mount("/prpc", prpc!(Proxy, AdminRpcHandler, trim: "Admin."))
                .manage(admin_state)
                .launch()
                .await
        } else {
            std::future::pending().await
        }
    };
    let debug_srv = async move {
        if debug_config.insecure_enable_debug_rpc {
            rocket::custom(debug_figment)
                .mount("/prpc", prpc!(Proxy, DebugRpcHandler, trim: "Debug."))
                .mount("/", web_routes::health_routes())
                .manage(debug_state)
                .launch()
                .await
        } else {
            std::future::pending().await
        }
    };
    tokio::select! {
        result = main_srv => {
            result.map_err(|err| anyhow!("Failed to start main server: {err:?}"))?;
        }
        result = admin_srv => {
            result.map_err(|err| anyhow!("Failed to start admin server: {err:?}"))?;
        }
        result = debug_srv => {
            result.map_err(|err| anyhow!("Failed to start debug server: {err:?}"))?;
        }
    }
    Ok(())
}
