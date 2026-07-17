// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use gpu_attest_proxy::cache::Cache;
use gpu_attest_proxy::proxy::{refresh_loop, rocket, ProxyConfig, ProxyState};
use load_config::load_config;
use rocket::figment::Figment;
use tracing::error;
use tracing_subscriber::EnvFilter;

pub const DEFAULT_CONFIG: &str = include_str!("../gpu-attest-proxy.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("gpu-attest-proxy", DEFAULT_CONFIG, config_file, false)
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
}

fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    if let Err(err) = async_main(args) {
        error!("{err:?}");
        return Err(err);
    }
    Ok(())
}

#[tokio::main]
async fn async_main(args: Args) -> Result<()> {
    let mut figment = load_config_figment(args.config.as_deref());
    if let Some(address) = args.address {
        figment = figment.join(("address", address));
    }
    if let Some(port) = args.port {
        figment = figment.join(("port", port));
    }
    let config: ProxyConfig = figment.extract().context("failed to parse config")?;
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;
    let cache = Cache::load(&config.cache_dir, config.rim_max_stale.as_secs())
        .context("failed to load collateral cache")?;
    let state = Arc::new(ProxyState {
        config,
        cache,
        http,
    });
    tokio::spawn(refresh_loop(state.clone()));
    let rocket = rocket(figment, state);
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("{err:?}"))
        .context("failed to ignite rocket")?;
    ignite
        .launch()
        .await
        .map_err(|err| anyhow!("{err:?}"))
        .context("failed to launch rocket")?;
    Ok(())
}
