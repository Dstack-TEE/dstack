// SPDX-FileCopyrightText: 2024-2025 Phala Network dstack@phala.network
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Parser;
use config::{Config, TlsConfig};
use dstack_guest_agent_rpc::{GetTlsKeyArgs, dstack_guest_client::DstackGuestClient};
use dstack_kms_rpc::SignCertRequest;
use http_client::prpc::PrpcClient;
use ra_rpc::{client::RaClient, prpc_routes as prpc, rocket_helper::QuoteVerifier};
use ra_tls::rcgen::KeyPair;
use ra_tls::{
    attestation::AttestationVerifier,
    cert::{CertConfigV2, CertSigningRequestV2, Csr},
};
use rocket::{
    fairing::AdHoc,
    figment::{Figment, providers::Serialized},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use admin_service::AdminRpcHandler;
use main_service::{Proxy, ProxyOptions, RpcHandler};

use crate::debug_service::DebugRpcHandler;

mod admin_auth;
mod admin_service;
mod cert_store;
mod config;
mod debug_service;
mod distributed_certbot;
mod kv;
mod main_service;
mod models;
mod pp;
mod proxy;
mod web_routes;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugKeyData {
    /// Private key in PEM format
    key_pem: String,
    /// TDX quote in base64 format
    quote_base64: String,
    /// Event log in JSON string format
    event_log: String,
    /// VM config in JSON string format
    vm_config: String,
}

#[global_allocator]
static ALLOCATOR: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn app_version() -> String {
    dstack_build_info::app_version!()
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
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
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
            with_app_info: true,
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

    // Check if debug key file is configured
    if config.debug.key_file.is_empty() {
        info!("Debug key file not configured, skipping cert generation");
        return Ok(());
    }

    // Load pre-generated key pair and quote data from JSON file
    info!("Loading debug key data from: {}", config.debug.key_file);
    let ctx = "Failed to read debug key, run `cargo run --bin gen_debug_key -- <simulator_url>` to generate it";
    let json_content = fs_err::read_to_string(&config.debug.key_file).context(ctx)?;
    let debug_data: DebugKeyData =
        serde_json::from_str(&json_content).context("Failed to parse debug key JSON")?;

    let key_pem = debug_data.key_pem;
    let quote_bin = STANDARD
        .decode(&debug_data.quote_base64)
        .context("Failed to decode quote from base64")?;
    let event_log_json = debug_data.event_log;
    let vm_config_json = debug_data.vm_config;

    // Parse key pair
    let key = KeyPair::from_pem(&key_pem).context("Failed to parse debug key")?;
    let pubkey = key.public_key_der();

    // Build CSR with attestation from debug quote
    let attestation =
        ra_tls::attestation::Attestation::from_tdx_quote(quote_bin, event_log_json.as_bytes())
            .context("Failed to create attestation from debug quote")?
            .into_versioned();

    let csr = CertSigningRequestV2 {
        confirm: "please sign cert:".to_string(),
        pubkey,
        config: CertConfigV2 {
            org_name: None,
            subject: "dstack-gateway".to_string(),
            subject_alt_names: alt_names,
            usage_server_auth: true,
            usage_client_auth: true,
            ext_quote: true,
            ext_app_info: true,
            not_before: None,
            not_after: None,
        },
        attestation,
    };
    let signature = csr.signed_by(&key).context("Failed to sign CSR")?;

    // Send CSR to KMS for signing
    let kms_url = format!("{kms_url}/prpc");
    info!("Sending CSR to KMS for signing: {kms_url}");
    let kms_client = RaClient::new(kms_url, true).context("Failed to create kms client")?;
    let kms_client = dstack_kms_rpc::kms_client::KmsClient::new(kms_client);
    let sign_response = kms_client
        .sign_cert(SignCertRequest {
            api_version: 2,
            csr: csr.to_vec(),
            signature,
            vm_config: vm_config_json.to_string(),
        })
        .await
        .context("Failed to sign certificate via KMS")?;

    let ca_cert = sign_response
        .certificate_chain
        .last()
        .context("Empty certificate chain")?
        .to_string();
    let certs = sign_response.certificate_chain.join("\n");

    write_cert(&tls_config.mutual.ca_certs, &ca_cert)?;
    write_cert(&tls_config.certs, &certs)?;
    write_cert(&tls_config.key, &key.serialize_pem())?;
    Ok(())
}

fn write_cert(path: &str, cert: &str) -> Result<()> {
    info!("Writing cert to file: {path}");
    safe_write::safe_write(path, cert)?;
    Ok(())
}

#[rocket::main]
fn public_rpc_routes() -> Vec<rocket::Route> {
    prpc!(Proxy, RpcHandler, trim: "Gateway.")
}

fn admin_rpc_routes() -> Vec<rocket::Route> {
    prpc!(Proxy, AdminRpcHandler, trim: "Admin.")
}

fn debug_rpc_routes() -> Vec<rocket::Route> {
    prpc!(Proxy, DebugRpcHandler, trim: "Debug.")
}

async fn main() -> Result<()> {
    {
        use tracing_subscriber::{EnvFilter, fmt};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());

    let mut config = figment.focus("core").extract::<Config>()?;
    // Validate node_id
    if config.sync.enabled && config.sync.node_id == 0 {
        anyhow::bail!("node_id must be greater than 0");
    }
    if config.debug.insecure_localhost_backend {
        warn!(
            "core.debug.insecure_localhost_backend = true; the app address \"localhost\" now \
             resolves to 127.0.0.1 on this host. App addresses also come from the \
             _dstack-app-address TXT record of arbitrary custom domains, so any DNS zone owner \
             can reach this host's loopback on a port of their choosing, bypassing port_policy. \
             Never use this outside local development"
        );
    }
    // Before anything reads `proxy.ktls`: the acceptor built later decides
    // whether to extract session secrets from it.
    proxy::disable_ktls_if_unsupported(&mut config.proxy);

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
    let attestation_verifier = Arc::new(
        AttestationVerifier::load(&config.attestation)
            .context("failed to load attestation verifier")?,
    );
    let admin_auth = if config.admin.enabled {
        Some(admin_auth::AdminAuthFairing::from_config(&config.admin)?)
    } else {
        None
    };
    let admin_insecure = config.admin.insecure_no_auth;
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
        .mount("/prpc", public_rpc_routes())
        .mount("/", web_routes::health_routes())
        .mount("/", web_routes::dashboard_alias_routes())
        // Mount WaveKV sync endpoint (requires mTLS gateway auth)
        .mount("/", web_routes::wavekv_sync_routes())
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .manage(state.clone());
    let verifier = QuoteVerifier::new(attestation_verifier);
    rocket = rocket.manage(verifier);
    let main_srv = rocket.launch();
    let admin_state = state.clone();
    let debug_state = state;
    let admin_srv = async move {
        if let Some(auth_fairing) = admin_auth {
            if admin_insecure {
                tracing::warn!(
                    "admin server running with insecure_no_auth = true; admin API is exposed without authentication"
                );
            } else {
                tracing::info!("admin server authentication enabled");
            }
            rocket::custom(admin_figment)
                .attach(auth_fairing)
                .mount("/", admin_auth::routes())
                .mount("/", web_routes::routes())
                .mount("/", web_routes::health_routes())
                .mount("/", web_routes::dashboard_alias_routes())
                .mount("/", admin_rpc_routes())
                .mount("/prpc", admin_rpc_routes())
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
                .mount("/prpc", debug_rpc_routes())
                .mount("/", web_routes::health_routes())
                .mount("/", web_routes::dashboard_alias_routes())
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

#[cfg(test)]
mod route_tests {
    use super::{admin_rpc_routes, debug_rpc_routes, public_rpc_routes};
    use std::collections::BTreeSet;

    fn paths(routes: Vec<rocket::Route>) -> BTreeSet<String> {
        routes
            .into_iter()
            .map(|route| route.uri.to_string())
            .collect()
    }

    #[test]
    fn gateway_internal_batch_008_rpc_route_exposure_matrix() {
        let public = paths(public_rpc_routes());
        let admin = paths(admin_rpc_routes());
        let debug = paths(debug_rpc_routes());

        for expected in ["/RegisterCvm", "/AcmeInfo", "/Info", "/GetPeers"] {
            assert!(public.contains(expected), "missing public route {expected}");
        }
        for forbidden in [
            "/Status",
            "/Exit",
            "/SetNodeStatus",
            "/SetInstancePortPolicy",
            "/ClearInstancePortPolicy",
        ] {
            assert!(
                !public.contains(forbidden),
                "admin route exposed publicly: {forbidden}"
            );
            assert!(
                admin.contains(forbidden),
                "admin route missing: {forbidden}"
            );
        }
        for forbidden in ["/GetSyncData", "/GetProxyState"] {
            assert!(
                !public.contains(forbidden),
                "debug route exposed publicly: {forbidden}"
            );
            assert!(
                debug.contains(forbidden),
                "debug route missing: {forbidden}"
            );
        }
        assert!(public.is_disjoint(&admin));
        assert!(
            !public.is_disjoint(&debug),
            "shared Info/RegisterCvm routes expected"
        );
    }
}
