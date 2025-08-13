use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use certbot::{CertBotConfig, WorkDir};
use clap::Parser;
use documented::DocumentedFields;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use toml_edit::ser::to_document;

#[derive(Parser)]
enum Command {
    /// Automatically renew certificates if they are close to expiration
    Renew {
        /// Path to the configuration file
        #[arg(short, long, default_value = "certbot.toml")]
        config: PathBuf,
        /// Run only once and exit
        #[arg(long)]
        once: bool,
        /// Force renewal
        #[arg(long)]
        force: bool,
    },
    /// Initialize the configuration file
    Init {
        /// Path to the configuration file
        #[arg(short, long, default_value = "certbot.toml")]
        config: PathBuf,
    },
    /// Set CAA record for the domain
    SetCaa {
        /// Path to the configuration file
        #[arg(short, long, default_value = "certbot.toml")]
        config: PathBuf,
    },
    /// Generate configuration template
    Cfg {
        /// Write to file
        #[arg(short, long)]
        write_to: Option<PathBuf>,
    },
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Deserialize, Serialize, DocumentedFields)]
struct Config {
    /// Path to the working directory
    workdir: PathBuf,
    /// ACME server URL
    acme_url: String,
    /// Cloudflare API token
    cf_api_token: String,
    /// Cloudflare zone ID
    cf_zone_id: String,
    /// Auto set CAA record
    auto_set_caa: bool,
    /// List of domains to issue certificates for
    domains: Vec<String>,
    /// Renew interval in seconds
    renew_interval: u64,
    /// Number of days before expiration to trigger renewal
    renew_days_before: u64,
    /// Renew timeout in seconds
    renew_timeout: u64,
    /// Command to run after renewal
    #[serde(default)]
    renewed_hook: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            workdir: ".".into(),
            acme_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            cf_api_token: "".into(),
            cf_zone_id: "".into(),
            auto_set_caa: true,
            domains: vec!["example.com".into()],
            renew_interval: 3600,
            renew_days_before: 10,
            renew_timeout: 120,
            renewed_hook: None,
        }
    }
}

impl Config {
    fn to_commented_toml(&self) -> Result<String> {
        let mut doc = to_document(self)?;

        for (i, (mut key, _value)) in doc.iter_mut().enumerate() {
            let decor = key.leaf_decor_mut();
            let docstring = Self::FIELD_DOCS[i];

            let mut comment = String::new();
            for line in docstring.lines() {
                let line = if line.is_empty() {
                    String::from("#\n")
                } else {
                    format!("# {line}\n")
                };
                comment.push_str(&line);
            }
            decor.set_prefix(comment);
        }
        Ok(doc.to_string())
    }
}

fn load_config(config: &PathBuf) -> Result<CertBotConfig> {
    let config: Config = toml_edit::de::from_str(&fs::read_to_string(config)?)?;
    let workdir = WorkDir::new(&config.workdir);
    let renew_interval = Duration::from_secs(config.renew_interval);
    let renew_expires_in = Duration::from_secs(config.renew_days_before * 24 * 60 * 60);
    let renew_timeout = Duration::from_secs(config.renew_timeout);
    let bot_config = CertBotConfig::builder()
        .acme_url(config.acme_url)
        .cert_dir(workdir.cert_backup_dir())
        .cert_file(workdir.cert_path())
        .key_file(workdir.key_path())
        .auto_create_account(true)
        .cert_subject_alt_names(config.domains)
        .cf_zone_id(config.cf_zone_id)
        .cf_api_token(config.cf_api_token)
        .renew_interval(renew_interval)
        .renew_timeout(renew_timeout)
        .renew_expires_in(renew_expires_in)
        .credentials_file(workdir.account_credentials_path())
        .auto_set_caa(config.auto_set_caa)
        .maybe_renewed_hook(config.renewed_hook)
        .build();
    Ok(bot_config)
}

async fn renew(config: &PathBuf, once: bool, force: bool) -> Result<()> {
    let bot_config = load_config(config).context("Failed to load configuration")?;
    let bot = bot_config
        .build_bot()
        .await
        .context("Failed to build bot")?;
    if once {
        bot.renew(force).await?;
    } else {
        bot.run().await;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let args = Args::parse();
    match args.command {
        Command::Renew {
            config,
            once,
            force,
        } => {
            renew(&config, once, force).await?;
        }
        Command::Init { config } => {
            let config = load_config(&config).context("Failed to load configuration")?;
            // The build_bot() will trigger the initialization and create Account if not exists
            let _bot = config.build_bot().await.context("Failed to build bot")?;
        }
        Command::SetCaa { config } => {
            let bot_config = load_config(&config).context("Failed to load configuration")?;
            let bot = bot_config
                .build_bot()
                .await
                .context("Failed to build bot")?;
            bot.set_caa().await?;
        }
        Command::Cfg { write_to } => {
            let toml_str = Config::default().to_commented_toml()?;
            match write_to {
                Some(path) => fs::write(path, toml_str)?,
                None => println!("{}", toml_str),
            }
        }
    }
    Ok(())
}
