use anyhow::{anyhow, Result};
use clap::Parser;
use config::{Config, TlsConfig};
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

    #[cfg(unix)]
    if config.set_ulimit {
        set_max_ulimit()?;
    }

    let proxy_config = config.proxy.clone();
    let pccs_url = config.pccs_url.clone();
    let admin_enabled = config.admin.enabled;
    let state = main_service::Proxy::new(config).await?;
    state.lock().reconfigure()?;
    proxy::start(proxy_config, state.clone());

    let admin_figment =
        Figment::new()
            .merge(rocket::Config::default())
            .merge(Serialized::defaults(
                figment
                    .find_value("core.admin")
                    .context("admin section not found")?,
            ));

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
        if admin_enabled {
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
