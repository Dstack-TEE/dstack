// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-vmm-top`: watch one or many dstack-vmm nodes from one terminal.
//!
//! ```text
//!   dstack-vmm-top                         this host's VMMs (auto-discovered)
//!   dstack-vmm-top -n tdx-01=http://10.0.0.11:9080 -n tdx-02=http://10.0.0.12:9080
//!   dstack-vmm-top --hub https://vmm-hub.example:9970
//!   dstack-vmm-top serve --listen 0.0.0.0:9970     run a hub for others to watch
//! ```
//!
//! The TUI is only ever a client: it reads each node's VMM API directly, or
//! reads a hub (`serve`) that polls many nodes on its behalf. See `source.rs`
//! and `serve.rs`.

mod collector;
mod config;
mod fmt;
mod once;
mod serve;
mod snapshot;
mod source;
mod tui;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
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
    after_help = "With no --node, --hub or config file, watches the VMMs running on this host.\n\
                  Config file: ~/.config/dstack/vmm-top.toml (see --help of `serve` for the hub)."
)]
struct Cli {
    /// Config file listing nodes and hubs. Default: ~/.config/dstack/vmm-top.toml.
    #[arg(long, short = 'c', value_name = "FILE")]
    config: Option<PathBuf>,

    /// A VMM to watch: `unix:/path/vmm.sock` or `http(s)://host:port`, optionally
    /// named as `NAME=URL`. Repeatable.
    #[arg(long = "node", short = 'n', value_name = "[NAME=]URL")]
    nodes: Vec<String>,

    /// A hub (`dstack-vmm-top serve`) to watch every node behind. Repeatable.
    #[arg(long = "hub", value_name = "[NAME=]URL")]
    hubs: Vec<String>,

    /// Bearer token for VMMs that name none (`[auth]` enabled).
    #[arg(long, env = "DSTACK_VMM_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Bearer token for hubs that name none.
    #[arg(long, env = "DSTACK_VMM_TOP_TOKEN", hide_env_values = true)]
    hub_token: Option<String>,

    /// Poll interval, e.g. `1s`, `5s`. `+` / `-` change it live.
    #[arg(long, short = 'i', value_parser = humantime::parse_duration)]
    interval: Option<Duration>,

    /// Print one plain-text snapshot and exit. Implied when stdout is not a terminal.
    #[arg(long)]
    once: bool,

    /// Print one JSON snapshot and exit.
    #[arg(long, conflicts_with = "once")]
    json: bool,

    /// Never start, shut down or stop a VM from this terminal.
    #[arg(long)]
    read_only: bool,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a hub: poll the configured VMMs and serve them, read-only, to TUIs.
    ///
    /// Sources are chosen as for the TUI (config file, --node, discovery).
    /// Watch it with `dstack-vmm-top --hub http://HOST:PORT`.
    Serve {
        /// `HOST:PORT` or `unix:/path`. Default: [serve] listen, else 127.0.0.1:9970.
        #[arg(long)]
        listen: Option<String>,
        /// Name the hub reports. Default: [serve] name, else the host name.
        #[arg(long)]
        name: Option<String>,
        /// Token clients must send. Falls back to [serve] token / token_env,
        /// then DSTACK_VMM_TOP_TOKEN.
        #[arg(long, hide_env_values = true)]
        auth_token: Option<String>,
        /// Allow a non-loopback listen address without a token.
        #[arg(long)]
        insecure: bool,
    },
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
    let read_only = cli.read_only || file.read_only;
    let specs = config::sources(
        &file,
        config::Flags {
            nodes: &cli.nodes,
            hubs: &cli.hubs,
            token: cli.token.as_deref(),
            hub_token: cli.hub_token.as_deref(),
        },
    )?;
    let sources = specs
        .into_iter()
        .map(|s| Source::new(s, read_only))
        .collect::<Result<Vec<_>>>()?;

    if let Some(Cmd::Serve {
        listen,
        name,
        auth_token,
        insecure,
    }) = cli.command
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with_writer(std::io::stderr)
            .init();
        let token = match auth_token {
            Some(t) => Some(t),
            None => {
                config::resolve_token(file.serve.token.as_deref(), file.serve.token_env.as_deref())?
                    .or_else(|| std::env::var(config::HUB_TOKEN_ENV).ok())
                    .filter(|t| !t.trim().is_empty())
            }
        };
        let opts = serve::Options {
            name: name.or(file.serve.name.clone()).unwrap_or_else(hostname),
            listen: listen
                .or(file.serve.listen.clone())
                .unwrap_or_else(|| "127.0.0.1:9970".into()),
            token,
            interval_ms,
            insecure,
        };
        return serve::run(sources, opts).await;
    }

    if sources.is_empty() {
        bail!(
            "no VMM to watch: none is registered on this host and no {} exists.\n\
             Give one with --node URL, a hub with --hub URL, or list them in {}",
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
    tui::run(sources, interval_ms, read_only).await
}

fn hostname() -> String {
    fs_err::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "vmm-hub".into())
}
