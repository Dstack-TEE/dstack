// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use load_config::load_config;
use rocket::{
    fairing::AdHoc,
    figment::Figment,
    listener::{Bind, DefaultListener},
};
use supervisor::web_api;
use tracing::error;
use tracing_subscriber::EnvFilter;

pub const DEFAULT_CONFIG: &str = include_str!("../supervisor.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("supervisor", DEFAULT_CONFIG, config_file, true)
}

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
    /// bind address
    #[arg(short, long)]
    address: Option<String>,
    /// bind port
    #[arg(short, long)]
    port: Option<u16>,
    /// bind on unix domain socket
    #[arg(short, long)]
    uds: Option<String>,
    /// remove existing socket
    #[arg(long)]
    remove_existing_uds: bool,
    /// detach from terminal
    #[cfg(unix)]
    #[arg(short, long)]
    detach: bool,
    /// pid file
    #[arg(long)]
    pid_file: Option<String>,
    /// log file
    #[arg(long)]
    log_file: Option<String>,
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

fn main() -> Result<()> {
    // Set max ulimit for file descriptors
    #[cfg(unix)]
    if let Err(err) = set_max_ulimit() {
        error!("Failed to set max ulimit: {err:?}");
    }

    let args = Args::parse();
    if let Some(log_file) = &args.log_file {
        mk_parents(log_file)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .context("Failed to open log file")?;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_writer(file)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }
    #[cfg(unix)]
    if args.detach {
        // run in background
        let ret = unsafe { libc::daemon(1, 0) };
        if ret != 0 {
            error!("Failed to run in background, error code: {ret}");
            bail!("Failed to run in background, error code: {ret}");
        }
    }
    if let Err(err) = async_main(args) {
        error!("{err:?}");
        return Err(err);
    }
    Ok(())
}

#[tokio::main]
async fn async_main(args: Args) -> Result<()> {
    let mut figment = load_config_figment(args.config.as_deref());
    if let Some(uds) = args.uds {
        mk_parents(&uds)?;
        if args.remove_existing_uds {
            fs_err::remove_file(&uds).ok();
        }
        figment = figment.join(("address", format!("unix:{uds}")));
    } else if let Some(address) = args.address {
        figment = figment.join(("address", address));
    }
    if let Some(port) = args.port {
        figment = figment.join(("port", port));
    }
    let rocket = web_api::rocket(figment);
    let rocket = rocket.attach(AdHoc::on_response("Add app version header", |_req, res| {
        Box::pin(async move {
            res.set_raw_header("X-App-Version", app_version());
        })
    }));
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("{err:?}"))
        .context("Failed to ignite rocket")?;
    let endpoint = DefaultListener::bind_endpoint(&ignite)
        .map_err(|err| anyhow!("{err:?}"))
        .context("Failed to get endpoint")?;
    let listener = DefaultListener::bind(&ignite)
        .await
        .map_err(|err| anyhow!("{err:?}"))
        .context(format!("Failed to bind on {endpoint}"))?;
    if let Some(pid_file) = &args.pid_file {
        mk_parents(pid_file)?;
        let pid = std::process::id();
        fs_err::write(pid_file, pid.to_string()).context("Failed to write pid file")?;
    }
    ignite
        .launch_on(listener)
        .await
        .map_err(|err| anyhow!("{err:?}"))
        .context("Failed to launch rocket")?;
    Ok(())
}

fn mk_parents(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs_err::create_dir_all(parent).context("Failed to create parent directory")?;
    Ok(())
}
