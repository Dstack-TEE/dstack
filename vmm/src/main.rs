use std::path::Path;

use anyhow::{anyhow, Context, Result};
use app::App;
use clap::Parser;
use config::Config;
use guest_api_service::GuestApiHandler;
use host_api_service::HostApiHandler;
use main_service::RpcHandler;
use path_absolutize::Absolutize;
use rocket::{
    fairing::AdHoc,
    figment::{providers::Serialized, Figment},
};
use rocket_apitoken::ApiToken;
use rocket_vsock_listener::VsockListener;
use supervisor_client::SupervisorClient;

mod app;
mod config;
mod guest_api_service;
mod host_api_service;
mod main_routes;
mod main_service;

const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_REV: &str = git_version::git_version!(
    args = ["--abbrev=20", "--always", "--dirty=-modified"],
    prefix = "git:",
    fallback = "unknown"
);

fn app_version() -> String {
    format!("v{CARGO_PKG_VERSION} ({GIT_REV})")
}

#[derive(Parser)]
#[command(author, version, about, long_version = app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

async fn run_external_api(app: App, figment: Figment, api_auth: ApiToken) -> Result<()> {
    let external_api = rocket::custom(figment)
        .mount("/", main_routes::routes())
        .mount("/guest", ra_rpc::prpc_routes!(App, GuestApiHandler))
        .mount("/api", ra_rpc::prpc_routes!(App, HostApiHandler))
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(App, RpcHandler, trim: "Teepod."),
        )
        .manage(app)
        .manage(api_auth)
        .attach(AdHoc::on_response("Add app rev header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .attach(AdHoc::on_response("Disable buffering", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-Accel-Buffering", "no");
            })
        }));

    let _ = external_api
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

async fn run_host_api(app: App, figment: Figment) -> Result<()> {
    let figment = figment
        .clone()
        .merge(Serialized::defaults(figment.find_value("host_api")?));
    let rocket = rocket::custom(figment)
        .mount("/api", ra_rpc::prpc_routes!(App, HostApiHandler))
        .manage(app);
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;
    let listener = VsockListener::bind_rocket(&ignite)
        .map_err(|err| anyhow!("Failed to bind host API : {err}"))?;
    ignite
        .launch_on(listener)
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
    let config = Config::extract_or_default(&figment)?.abs_path()?;
    let api_auth = ApiToken::new(config.auth.tokens.clone(), config.auth.enabled);
    let supervisor = {
        let cfg = &config.supervisor;
        let abs_exe = Path::new(&cfg.exe).absolutize()?;
        SupervisorClient::start_and_connect_uds(
            &abs_exe,
            &cfg.sock,
            &cfg.pid_file,
            &cfg.log_file,
            cfg.detached,
            cfg.auto_start,
        )
        .await
        .context("Failed to connect to supervisor")?
    };
    let state = app::App::new(config, supervisor);
    state.reload_vms().await.context("Failed to reload VMs")?;

    tokio::select! {
        result = run_external_api(state.clone(), figment.clone(), api_auth) => {
            result.context("Failed to run external API")?;
        }
        result = run_host_api(state, figment) => {
            result.context("Failed to run host API")?;
        }
    }
    Ok(())
}
