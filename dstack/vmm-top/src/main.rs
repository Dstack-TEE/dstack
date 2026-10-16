// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-vmm-top`: watch one or many dstack-vmm nodes from one terminal.
//!
//! ```text
//!   dstack-vmm-top                         this host's VMMs (auto-discovered)
//!   dstack-vmm-top -n tdx-01=http://10.0.0.11:9080 -n tdx-02=http://10.0.0.12:9080
//! ```
//!
//! The TUI is only ever a client of each node's VMM API. See `source.rs`.

mod collector;
mod config;
mod fmt;
mod once;
mod snapshot;
mod source;
mod tui;

use anyhow::{bail, Context, Result};
use clap::Parser;
use source::Source;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Parser)]
#[command(
    name = "dstack-vmm-top",
    version,
    about = "watch one or many dstack-vmm nodes from one terminal",
    after_help = "With no --node or config file, watches the VMMs running on this host.\n\
                  Config file: ~/.config/dstack/vmm-top.toml."
)]
struct Cli {
    /// Config file listing nodes. Default: ~/.config/dstack/vmm-top.toml.
    #[arg(long, short = 'c', value_name = "FILE")]
    config: Option<PathBuf>,

    /// A VMM to watch: `unix:/path/vmm.sock` or `http(s)://host:port`, optionally
    /// named as `NAME=URL`. Repeatable.
    #[arg(long = "node", short = 'n', value_name = "[NAME=]URL")]
    nodes: Vec<String>,

    /// Bearer token for VMMs that name none (`[auth]` enabled).
    #[arg(long, env = "DSTACK_VMM_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Poll interval, e.g. `1s`, `5s`. `+` / `-` change it live.
    #[arg(long, short = 'i', value_parser = humantime::parse_duration)]
    interval: Option<Duration>,

    /// Print one plain-text snapshot and exit. Implied when stdout is not a terminal.
    #[arg(long)]
    once: bool,

    /// Print one JSON snapshot and exit.
    #[arg(long, conflicts_with = "once")]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let file = config::load(cli.config.as_deref())?;
    let interval = match (cli.interval, &file.interval) {
        (Some(d), _) => d,
        (None, Some(s)) => humantime::parse_duration(s)
            .with_context(|| format!("invalid interval '{s}' in config"))?,
        (None, None) => DEFAULT_INTERVAL,
    };
    let interval_ms = (interval.as_millis() as u64).max(200);
    let specs = config::sources(
        &file,
        config::Flags {
            nodes: &cli.nodes,
            token: cli.token.as_deref(),
        },
    )?;
    let sources = specs
        .into_iter()
        .map(Source::new)
        .collect::<Result<Vec<_>>>()?;

    if sources.is_empty() {
        bail!(
            "no VMM to watch: none is registered on this host and no {} exists.\n\
             Give one with --node URL, or list them in {}",
            config::DEFAULT_SOCKET,
            config::default_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "a config file".into())
        );
    }
    let interactive = std::io::stdout().is_terminal() && std::io::stdin().is_terminal();
    if cli.json || cli.once || !interactive {
        return once::run(sources, cli.json).await;
    }
    tui::run(sources, interval_ms).await
}
