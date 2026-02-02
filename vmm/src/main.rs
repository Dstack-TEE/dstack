// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{path::Path, time::Duration};

use anyhow::{anyhow, Context, Result};
use app::App;
use clap::{Args as ClapArgs, Parser, Subcommand};
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
use tracing::{error, info};

mod app;
mod config;
mod guest_api_service;
mod host_api_service;
mod main_routes;
mod main_service;
mod one_shot;
mod openapi;

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
    /// Subcommand to run
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Default, Subcommand)]
enum Command {
    /// Start the VMM server (default mode)
    #[default]
    Serve,
    /// One-shot VM execution mode for debugging
    Run(RunArgs),
}

#[derive(ClapArgs)]
struct RunArgs {
    /// VM configuration file path
    vm_config: String,
    /// Working directory for one-shot mode (default: create in current directory)
    #[arg(long)]
    workdir: Option<String>,
    /// Dry run: only output QEMU command without executing
    #[arg(long)]
    dry_run: bool,
}

async fn run_external_api(app: App, figment: Figment, api_auth: ApiToken) -> Result<()> {
    let version = app_version();
    let openapi_doc = openapi::build_openapi_doc(&version)?;

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
    let external_api =
        ra_rpc::rocket_helper::mount_openapi_docs(external_api, openapi_doc, "/api-docs");

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
    // Host API only supports vsock listener (validated at startup)
    let listener = VsockListener::bind_rocket(&ignite)
        .map_err(|err| anyhow!("Failed to bind host API: {err}"))?;
    ignite
        .launch_on(listener)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

async fn auto_restart_task(app: App) {
    if !app.config.cvm.auto_restart.enabled {
        info!("Auto restart CVMs is disabled");
        return;
    }
    let mut interval =
        tokio::time::interval(Duration::from_secs(app.config.cvm.auto_restart.interval));
    loop {
        info!("Checking for exited VMs");
        if let Err(err) = app.try_restart_exited_vms().await {
            error!("Failed to restart exited VMs: {err:?}");
        }
        interval.tick().await;
    }
}

#[rocket::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());
    let config = Config::extract_or_default(&figment)?.abs_path()?;

    // Validate host API configuration
    config
        .host_api
        .validate()
        .context("Invalid host_api configuration")?;

    // Handle commands
    match args.command.unwrap_or_default() {
        Command::Run(run_args) => {
            // One-shot VM execution mode
            return one_shot::run_one_shot(
                &run_args.vm_config,
                config,
                run_args.workdir,
                run_args.dry_run,
            )
            .await;
        }
        Command::Serve => {
            // Default server mode - continue to main server logic
        }
    }

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
    tokio::spawn(auto_restart_task(state.clone()));

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
