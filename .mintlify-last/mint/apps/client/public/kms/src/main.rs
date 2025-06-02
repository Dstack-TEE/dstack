use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use config::KmsConfig;
use main_service::{KmsState, RpcHandler};
use ra_rpc::rocket_helper::QuoteVerifier;
use rocket::{
    fairing::AdHoc,
    figment::{providers::Serialized, Figment},
    response::content::RawHtml,
    Shutdown,
};
use tracing::{info, warn};

mod config;
// mod ct_log;
mod crypto;
mod main_service;
mod onboard_service;

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

async fn run_onboard_service(kms_config: KmsConfig, figment: Figment) -> Result<()> {
    use onboard_service::{OnboardHandler, OnboardState};

    #[rocket::get("/")]
    async fn index() -> RawHtml<&'static str> {
        RawHtml(include_str!("www/onboard.html"))
    }
    #[rocket::get("/finish")]
    fn finish(shutdown: Shutdown) -> &'static str {
        shutdown.notify();
        "OK"
    }

    if !kms_config.onboard.auto_bootstrap_domain.is_empty() {
        onboard_service::bootstrap_keys(&kms_config).await?;
        return Ok(());
    }

    let state = OnboardState::new(kms_config);
    let figment = figment
        .clone()
        .merge(Serialized::defaults(figment.find_value("core.onboard")?));

    // Remove section tls

    let _ = rocket::custom(figment)
        .mount("/", rocket::routes![index, finish])
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(OnboardState, OnboardHandler, trim: "Onboard."),
        )
        .manage(state)
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

#[rocket::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }
    let args = Args::parse();

    let figment = config::load_config_figment(args.config.as_deref());
    let config: KmsConfig = figment.focus("core").extract()?;

    if config.onboard.enabled && !config.keys_exists() {
        info!("Onboarding");
        run_onboard_service(config.clone(), figment.clone()).await?;
        if !config.keys_exists() {
            bail!("Failed to onboard");
        }
    }

    info!("Updating certs");
    if let Err(err) = onboard_service::update_certs(&config).await {
        warn!("Failed to update certs: {err}");
    };

    info!("Starting KMS");
    info!("Supported methods:");
    for method in main_service::rpc_methods() {
        info!("  /prpc/{method}");
    }

    let pccs_url = config.pccs_url.clone();
    let state = main_service::KmsState::new(config).context("Failed to initialize KMS state")?;
    let figment = figment
        .clone()
        .merge(Serialized::defaults(figment.find_value("rpc")?));
    let mut rocket = rocket::custom(figment)
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(KmsState, RpcHandler, trim: "KMS."),
        )
        .manage(state);

    let verifier = QuoteVerifier::new(pccs_url);
    rocket = rocket.manage(verifier);

    rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}
