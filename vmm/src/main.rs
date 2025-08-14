// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{path::Path, time::Duration};

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
    listener::{Bind, DefaultListener},
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
    /// One-shot mode: setup VM and execute QEMU command from VM configuration file
    #[arg(long)]
    one_shot: Option<String>,
    /// Working directory for one-shot mode (default: create in current directory)
    #[arg(long)]
    workdir: Option<String>,
    /// Dry run: only output QEMU command without executing (use with --one-shot)
    #[arg(long)]
    dry_run: bool,
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
    if DefaultListener::bind_endpoint(&ignite).is_ok() {
        let listener = DefaultListener::bind(&ignite)
            .await
            .map_err(|err| anyhow!("Failed to bind host API : {err}"))?;
        ignite
            .launch_on(listener)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
    } else {
        let listener = VsockListener::bind_rocket(&ignite)
            .map_err(|err| anyhow!("Failed to bind host API : {err}"))?;
        ignite
            .launch_on(listener)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
    }
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
        fmt().with_env_filter(filter).init();
    }

    let args = Args::parse();
    let figment = config::load_config_figment(args.config.as_deref());
    let config = Config::extract_or_default(&figment)?.abs_path()?;

    // Handle one-shot mode
    if let Some(vm_config_path) = args.one_shot {
        return one_shot::run_one_shot(&vm_config_path, config, args.workdir, args.dry_run).await;
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
