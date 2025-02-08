use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::{AdminConfig, Config, TlsConfig};
use http_client::prpc::PrpcClient;
use ra_rpc::{client::RaClient, rocket_helper::QuoteVerifier};
use rocket::{
    fairing::AdHoc,
    figment::{providers::Serialized, Figment},
};
use std::path::Path;
use tracing::info;

use admin_service::AdminRpcHandler;
use main_service::{Proxy, RpcHandler};

mod admin_service;
mod config;
mod main_service;
mod models;
mod proxy;
mod web_routes;

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

async fn maybe_gen_certs(config: &Config, tls_config: &TlsConfig) -> Result<()> {
    if config.tls_domain.is_empty() {
        info!("TLS domain is empty, skipping cert generation");
        return Ok(());
    }

    let tappd_socket = Path::new("/var/run/tappd.sock");
    if tappd_socket.exists() {
        info!("Using tappd for certificate generation");
        let http_client =
            PrpcClient::new_unix(tappd_socket.display().to_string(), "/prpc".to_string());
        let client = tappd_rpc::tappd_client::TappdClient::new(http_client);
        let response = client
            .derive_key(tappd_rpc::DeriveKeyArgs {
                path: "".to_string(),
                subject: "tproxy".to_string(),
                alt_names: vec![config.tls_domain.clone()],
                usage_ra_tls: true,
                usage_server_auth: true,
                usage_client_auth: false,
                random_seed: true,
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
        return Ok(());
    }

    let kms_url = config.kms_url.clone();
    if kms_url.is_empty() {
        info!("KMS URL is empty, skipping cert generation");
        return Ok(());
    }
    let kms_url = format!("{kms_url}/prpc");
    info!("Getting CA cert from {kms_url}");
    let client = RaClient::new(kms_url, true).context("Failed to create kms client")?;
    let client = kms_rpc::kms_client::KmsClient::new(client);
    let ca_cert = client.get_meta().await?.ca_cert;
    let key = ra_tls::rcgen::KeyPair::generate().context("Failed to generate key")?;
    let cert = ra_tls::cert::CertRequest::builder()
        .key(&key)
        .subject("tproxy")
        .alt_names(&[config.tls_domain.clone()])
        .usage_server_auth(true)
        .build()
        .self_signed()
        .context("Failed to self-sign rpc cert")?;

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
        fmt().with_env_filter(filter).init();
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());

    let config = figment.focus("core").extract::<Config>()?;
    config::setup_wireguard(&config.wg)?;

    let tls_config = figment.focus("tls").extract::<TlsConfig>()?;
    maybe_gen_certs(&config, &tls_config)
        .await
        .context("Failed to generate certs")?;

    #[cfg(unix)]
    if config.set_ulimit {
        set_max_ulimit()?;
    }

    let proxy_config = config.proxy.clone();
    let pccs_url = config.pccs_url.clone();
    let state = main_service::Proxy::new(config)?;
    state.lock().reconfigure()?;
    proxy::start(proxy_config, state.clone());

    let admin_figment = Figment::from(Serialized::defaults(
        figment
            .find_value("admin")
            .context("admin section not found")?,
    ));

    let admin_config = admin_figment
        .extract::<AdminConfig>()
        .context("Failed to parse admin config")?;

    let mut rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .mount("/prpc", ra_rpc::prpc_routes!(Proxy, RpcHandler))
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .manage(state.clone());
    let verifier = QuoteVerifier::new(pccs_url);
    rocket = rocket.manage(verifier);
    let main_srv = rocket.launch();
    let admin_srv = async move {
        if admin_config.enabled {
            rocket::custom(admin_figment)
                .mount("/", ra_rpc::prpc_routes!(Proxy, AdminRpcHandler))
                .manage(state)
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
    }
    Ok(())
}
