// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::Parser;
use dstack_guest_agent::{config, run_server, AppState};

#[derive(Parser)]
#[command(author, version, about, long_version = dstack_guest_agent::app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Enable systemd watchdog
    #[arg(short, long)]
    watchdog: bool,

    /// Run the internal, process-isolated NVML sampler.
    #[arg(long, hide = true)]
    gpu_info_helper: bool,
}

#[rocket::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // The helper's stdout is a machine-readable protocol pipe. Do not install
    // a tracing subscriber in this mode: the default formatter may write to
    // stdout, and NVML warnings must never corrupt protocol responses.
    if args.gpu_info_helper {
        return dstack_guest_agent::run_gpu_info_helper();
    }
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }
    let figment = config::load_config_figment(args.config.as_deref());
    let state = AppState::new(figment.focus("core").extract()?)
        .await
        .context("Failed to create app state")?;
    run_server(state, figment, args.watchdog).await
}
