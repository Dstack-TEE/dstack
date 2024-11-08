use anyhow::{anyhow, Result};
use clap::Parser;
use config::Config;
use ra_rpc::rocket_helper::QuoteVerifier;

mod config;
mod main_service;
mod models;
mod proxy;
mod web_routes;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

#[rocket::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());

    let config = figment.focus("core").extract::<Config>()?;
    let proxy_config = config.proxy.clone();
    let pccs_url = config.pccs_url.clone();
    let state = main_service::AppState::new(config)?;
    state.lock().reconfigure()?;
    proxy::start(proxy_config, state.clone());

    let mut rocket = rocket::custom(figment)
        .mount("/", web_routes::routes())
        .manage(state);
    if !pccs_url.is_empty() {
        let verifier = QuoteVerifier::new(pccs_url);
        rocket = rocket.manage(verifier);
    }
    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
