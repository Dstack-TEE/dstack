use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::KmsConfig;
use ra_rpc::rocket_helper::QuoteVerifier;
use tracing::info;

mod config;
mod ct_log;
mod main_service;
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
    let args = Args::parse();

    info!("Starting KMS");
    info!("Supported methods:");
    for method in main_service::rpc_methods() {
        info!("  /prpc/{method}");
    }

    let figment = config::load_config_figment(args.config.as_deref());
    let config: KmsConfig = figment.focus("core").extract()?;
    let pccs_url = config.pccs_url.clone();
    let state = main_service::KmsState::new(config).context("Failed to initialize KMS state")?;
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
