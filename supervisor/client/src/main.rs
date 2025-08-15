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
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }

    let cli = Cli::parse();
    let client = SupervisorClient::new(&cli.base_url);

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
            print_json(&client.deploy(&config).await?);
        }
        Commands::Start { id } => {
            print_json(&client.start(&id).await?);
        }
        Commands::Stop { id } => {
            print_json(&client.stop(&id).await?);
        }
        Commands::Remove { id } => {
            print_json(&client.remove(&id).await?);
        }
        Commands::List => {
            print_json(&client.list().await?);
        }
        Commands::Info { id } => {
            print_json(&client.info(&id).await?);
        }
        Commands::Ping => {
            print_json(&client.ping().await?);
        }
        Commands::Clear => {
            print_json(&client.clear().await?);
        }
        Commands::Shutdown => {
            print_json(&client.shutdown().await?);
        }
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) {
    println!("{}", serde_json::to_string(value).unwrap());
}
