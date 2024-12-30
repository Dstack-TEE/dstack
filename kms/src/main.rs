use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::KmsConfig;
use main_service::{KmsState, RpcHandler};
use ra_rpc::rocket_helper::QuoteVerifier;
use rocket::fairing::AdHoc;
use tracing::info;

mod config;
// mod ct_log;
mod main_service;
mod crypto;

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

#[rocket::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }
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
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .mount("/prpc", ra_rpc::prpc_routes!(KmsState, RpcHandler))
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
