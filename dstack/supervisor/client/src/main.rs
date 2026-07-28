// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::{Parser, Subcommand};
use supervisor::ProcessConfig;
use supervisor_client::SupervisorClient;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, default_value = "unix:/var/run/supervisor.sock")]
    base_url: String,

    /// Start a missing Supervisor before connecting to a trusted Unix socket.
    #[arg(long, requires_all = ["supervisor_path", "pid_file", "log_file"])]
    auto_start: bool,

    /// Supervisor executable used only with --auto-start.
    #[arg(long)]
    supervisor_path: Option<std::path::PathBuf>,

    /// PID file passed to an auto-started Supervisor.
    #[arg(long)]
    pid_file: Option<std::path::PathBuf>,

    /// Log file passed to an auto-started Supervisor.
    #[arg(long)]
    log_file: Option<std::path::PathBuf>,

    /// Detach an auto-started Supervisor process.
    #[arg(long, requires = "auto_start")]
    detached: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Deploy {
        #[arg(long)]
        id: String,
        #[arg(long)]
        command: String,
        #[arg(long = "arg")]
        args: Vec<String>,
    },
    Start {
        id: String,
    },
    Stop {
        id: String,
    },
    Remove {
        id: String,
    },
    List,
    Info {
        id: String,
    },
    Ping,
    Clear,
    Shutdown,
}

#[tokio::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{EnvFilter, fmt};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .init();
    }

    let cli = Cli::parse();
    let client = if cli.auto_start {
        let uds = cli
            .base_url
            .strip_prefix("unix:")
            .ok_or_else(|| anyhow::anyhow!("--auto-start requires a unix: base URL"))?;
        SupervisorClient::start_and_connect_uds(
            cli.supervisor_path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing --supervisor-path"))?,
            uds,
            cli.pid_file
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing --pid-file"))?,
            cli.log_file
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing --log-file"))?,
            cli.detached,
            true,
        )
        .await?
    } else {
        SupervisorClient::new(&cli.base_url)
    };

    match cli.command {
        Commands::Deploy { id, command, args } => {
            let config = ProcessConfig {
                id,
                name: String::new(),
                command,
                args,
                env: Default::default(),
                cwd: String::new(),
                stdout: String::new(),
                stderr: String::new(),
                pidfile: String::new(),
                cid: None,
                note: String::new(),
            };
            print_json(&client.deploy(&config).await?)?;
        }
        Commands::Start { id } => {
            print_json(&client.start(&id).await?)?;
        }
        Commands::Stop { id } => {
            print_json(&client.stop(&id).await?)?;
        }
        Commands::Remove { id } => {
            print_json(&client.remove(&id).await?)?;
        }
        Commands::List => {
            print_json(&client.list().await?)?;
        }
        Commands::Info { id } => {
            print_json(&client.info(&id).await?)?;
        }
        Commands::Ping => {
            print_json(&client.ping().await?)?;
        }
        Commands::Clear => {
            print_json(&client.clear().await?)?;
        }
        Commands::Shutdown => {
            print_json(&client.shutdown().await?)?;
        }
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}
