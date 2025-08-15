// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use bollard::container::{ListContainersOptions, RemoveContainerOptions};
use bollard::Docker;
use clap::{Parser, Subcommand};
use dstack_types::KeyProvider;
use fs_err as fs;
use getrandom::fill as getrandom;
use host_api::HostApi;
use k256::schnorr::SigningKey;
use ra_tls::{
    attestation::QuoteContentType,
    cert::generate_ra_cert,
    kdf::{derive_ecdsa_key, derive_ecdsa_key_pair_from_bytes},
    rcgen::KeyPair,
};
use scale::Decode;
use serde::Deserialize;
use std::{collections::HashMap, path::Path};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
use system_setup::{cmd_sys_setup, SetupArgs};
use tdx_attest as att;
use utils::AppKeys;

mod crypto;
mod host_api;
mod parse_env_file;
mod system_setup;
mod utils;

/// dstack guest utility
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get TDX report given report data from stdin
    Report,
    /// Generate a TDX quote given report data from stdin
    Quote,
    /// Extend RTMRs
    Extend(ExtendArgs),
    /// Show the current RTMR state
    Show,
    /// Hex encode data
    Hex(HexCommand),
    /// Generate a RA-TLS certificate
    GenRaCert(GenRaCertArgs),
    /// Generate a CA certificate
    GenCaCert(GenCaCertArgs),
    /// Generate app keys for an dstack app
    GenAppKeys(GenAppKeysArgs),
    /// Generate random data
    Rand(RandArgs),
    /// Prepare dstack system.
    Setup(SetupArgs),
    /// Notify the host about the dstack app
    NotifyHost(HostNotifyArgs),
    /// Remove orphaned containers
    RemoveOrphans(RemoveOrphansArgs),
}

#[derive(Parser)]
/// Hex encode data
struct HexCommand {
    #[clap(value_parser)]
    /// filename to hex encode
    filename: Option<String>,
}

#[derive(Parser)]
/// Extend RTMR
struct ExtendArgs {
    #[clap(short, long)]
    /// event name
    event: String,

    #[clap(short, long)]
    /// hex encoded payload of the event
    payload: String,
}

#[derive(Parser)]
/// Generate a certificate
struct GenRaCertArgs {
    /// CA certificate used to sign the RA certificate
    #[arg(long)]
    ca_cert: PathBuf,

    /// CA private key used to sign the RA certificate
    #[arg(long)]
    ca_key: PathBuf,

    #[arg(short, long)]
    /// file path to store the certificate
    cert_path: PathBuf,

    #[arg(short, long)]
    /// file path to store the private key
    key_path: PathBuf,
}

#[derive(Parser)]
/// Generate CA certificate
struct GenCaCertArgs {
    /// path to store the certificate
    #[arg(long)]
    cert: PathBuf,
    /// path to store the private key
    #[arg(long)]
    key: PathBuf,
    /// CA level
    #[arg(long, default_value_t = 1)]
    ca_level: u8,
}

#[derive(Parser)]
/// Generate app keys
struct GenAppKeysArgs {
    /// CA level
    #[arg(long, default_value_t = 1)]
    ca_level: u8,

    /// path to store the app keys
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Parser)]
/// Generate random data
struct RandArgs {
    /// number of bytes to generate
    #[arg(short = 'n', long, default_value_t = 20)]
    bytes: usize,

    /// output to file
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// hex encode output
    #[arg(short = 'x', long)]
    hex: bool,
}

#[derive(Parser)]
/// Test app feature. Print "true" if the feature is supported, otherwise print "false".
struct TestAppFeatureArgs {
    /// path to the app keys
    #[arg(short, long)]
    feature: String,

    /// path to the app compose file
    #[arg(short, long)]
    compose: String,
}

#[derive(Parser)]
/// Notify the host about the dstack app
struct HostNotifyArgs {
    #[arg(short, long)]
    url: Option<String>,
    /// event name
    #[arg(short, long)]
    event: String,
    /// event payload
    #[arg(short = 'd', long)]
    payload: String,
}

#[derive(Parser)]
/// Remove orphaned containers
struct RemoveOrphansArgs {
    /// path to the docker-compose.yaml file
    #[arg(short = 'f', long)]
    compose: String,
}

#[derive(Debug, Deserialize)]
struct ComposeConfig {
    name: Option<String>,
    services: HashMap<String, ComposeService>,
}

#[derive(Debug, Deserialize)]
struct ComposeService {}

fn cmd_quote() -> Result<()> {
    let mut report_data = [0; 64];
    io::stdin()
        .read_exact(&mut report_data)
        .context("Failed to read report data")?;
    let (_key_id, quote) = att::get_quote(&report_data, None).context("Failed to get quote")?;
    io::stdout()
        .write_all(&quote)
        .context("Failed to write quote")?;
    Ok(())
}

fn cmd_extend(extend_args: ExtendArgs) -> Result<()> {
    let payload = hex::decode(&extend_args.payload).context("Failed to decode payload")?;
    att::extend_rtmr3(&extend_args.event, &payload).context("Failed to extend RTMR")
}

fn cmd_report() -> Result<()> {
    let mut report_data = [0; 64];
    io::stdin()
        .read_exact(&mut report_data)
        .context("Failed to read report data")?;
    let report = att::get_report(&report_data).context("Failed to get report")?;
    io::stdout()
        .write_all(&report.0)
        .context("Failed to write report")?;
    Ok(())
}

fn cmd_rand(rand_args: RandArgs) -> Result<()> {
    let mut data = vec![0u8; rand_args.bytes];
    getrandom(&mut data).context("Failed to generate random data")?;
    if rand_args.hex {
        data = hex::encode(data).into_bytes();
    }
    io::stdout()
        .write_all(&data)
        .context("Failed to write random data")?;
    Ok(())
}

#[derive(Decode)]
struct ParsedReport {
    attributes: [u8; 8],
    xfam: [u8; 8],
    mrtd: [u8; 48],
    mrconfigid: [u8; 48],
    mrowner: [u8; 48],
    mrownerconfig: [u8; 48],
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
    servtd_hash: [u8; 48],
}

impl core::fmt::Debug for ParsedReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use hex_fmt::HexFmt as HF;

        f.debug_struct("ParsedReport")
            .field("attributes", &HF(&self.attributes))
            .field("xfam", &HF(&self.xfam))
            .field("mrtd", &HF(&self.mrtd))
            .field("mrconfigid", &HF(&self.mrconfigid))
            .field("mrowner", &HF(&self.mrowner))
            .field("mrownerconfig", &HF(&self.mrownerconfig))
            .field("rtmr0", &HF(&self.rtmr0))
            .field("rtmr1", &HF(&self.rtmr1))
            .field("rtmr2", &HF(&self.rtmr2))
            .field("rtmr3", &HF(&self.rtmr3))
            .field("servtd_hash", &HF(&self.servtd_hash))
            .finish()
    }
}

fn cmd_show_mrs() -> Result<()> {
    let attestation = ra_tls::attestation::Attestation::local()?;
    let app_info = attestation.decode_app_info(false)?;
    serde_json::to_writer_pretty(io::stdout(), &app_info)?;
    println!();
    Ok(())
}

fn cmd_hex(hex_args: HexCommand) -> Result<()> {
    fn hex_encode_io(io: &mut impl Read) -> Result<()> {
        loop {
            let mut buf = [0; 1024];
            let n = io.read(&mut buf).context("Failed to read from stdin")?;
            if n == 0 {
                break;
            }
            print!("{}", hex_fmt::HexFmt(&buf[..n]));
        }
        Ok(())
    }
    if let Some(filename) = hex_args.filename {
        let mut input =
            fs::File::open(&filename).context(format!("Failed to open {}", filename))?;
        hex_encode_io(&mut input)?;
    } else {
        hex_encode_io(&mut io::stdin())?;
    };
    Ok(())
}

fn cmd_gen_ra_cert(args: GenRaCertArgs) -> Result<()> {
    let ca_cert = fs::read_to_string(args.ca_cert)?;
    let ca_key = fs::read_to_string(args.ca_key)?;
    let cert_pair = generate_ra_cert(ca_cert, ca_key)?;
    fs::write(&args.cert_path, cert_pair.cert_pem).context("Failed to write certificate")?;
    fs::write(&args.key_path, cert_pair.key_pem).context("Failed to write private key")?;
    Ok(())
}

fn cmd_gen_ca_cert(args: GenCaCertArgs) -> Result<()> {
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::KmsRootCa.to_report_data(&pubkey);
    let (_, quote) = att::get_quote(&report_data, None).context("Failed to get quote")?;
    let event_logs = att::eventlog::read_event_logs().context("Failed to read event logs")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;

    let req = CertRequest::builder()
        .subject("App Root CA")
        .quote(&quote)
        .event_log(&event_log)
        .key(&key)
        .ca_level(args.ca_level)
        .build();

    let cert = req
        .self_signed()
        .context("Failed to self-sign certificate")?;
    fs::write(&args.cert, cert.pem()).context("Failed to write certificate")?;
    fs::write(&args.key, key.serialize_pem()).context("Failed to write private key")?;
    Ok(())
}

fn cmd_gen_app_keys(args: GenAppKeysArgs) -> Result<()> {
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let disk_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let k256_key = SigningKey::random(&mut rand::thread_rng());
    let app_keys = make_app_keys(key, disk_key, k256_key, args.ca_level, None)?;
    let app_keys = serde_json::to_string(&app_keys).context("Failed to serialize app keys")?;
    fs::write(&args.output, app_keys).context("Failed to write app keys")?;
    Ok(())
}

fn gen_app_keys_from_seed(seed: &[u8], mr: Option<Vec<u8>>) -> Result<AppKeys> {
    let key = derive_ecdsa_key_pair_from_bytes(seed, &["app-key".as_bytes()])?;
    let disk_key = derive_ecdsa_key_pair_from_bytes(seed, &["app-disk-key".as_bytes()])?;
    let k256_key = derive_ecdsa_key(seed, &["app-k256-key".as_bytes()], 32)?;
    let k256_key = SigningKey::from_bytes(&k256_key).context("Failed to parse k256 key")?;
    make_app_keys(key, disk_key, k256_key, 1, mr)
}

fn make_app_keys(
    app_key: KeyPair,
    disk_key: KeyPair,
    k256_key: SigningKey,
    ca_level: u8,
    mr: Option<Vec<u8>>,
) -> Result<AppKeys> {
    use ra_tls::cert::CertRequest;
    let pubkey = app_key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let (_, quote) = att::get_quote(&report_data, None).context("Failed to get quote")?;
    let event_logs = att::eventlog::read_event_logs().context("Failed to read event logs")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;
    let req = CertRequest::builder()
        .subject("App Root Cert")
        .quote(&quote)
        .event_log(&event_log)
        .key(&app_key)
        .ca_level(ca_level)
        .build();
    let cert = req
        .self_signed()
        .context("Failed to self-sign certificate")?;

    Ok(AppKeys {
        disk_crypt_key: sha256(&disk_key.serialize_der()).to_vec(),
        env_crypt_key: vec![],
        k256_key: k256_key.to_bytes().to_vec(),
        k256_signature: vec![],
        gateway_app_id: "".to_string(),
        ca_cert: cert.pem(),
        key_provider: match mr {
            Some(mr) => KeyProvider::Local {
                mr,
                key: app_key.serialize_pem(),
            },
            None => KeyProvider::None {
                key: app_key.serialize_pem(),
            },
        },
    })
}

async fn cmd_notify_host(args: HostNotifyArgs) -> Result<()> {
    let client = HostApi::load_or_default(args.url)?;
    client.notify(&args.event, &args.payload).await?;
    Ok(())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut sha256 = sha2::Sha256::new();
    sha256.update(data);
    sha256.finalize().into()
}

fn get_project_name(compose_file: impl AsRef<Path>) -> Result<String> {
    let project_name = fs::canonicalize(compose_file)
        .context("Failed to canonicalize compose file")?
        .parent()
        .context("Failed to get parent directory of compose file")?
        .file_name()
        .context("Failed to get file name of compose file")?
        .to_string_lossy()
        .into_owned();
    Ok(project_name)
}

async fn cmd_remove_orphans(compose_file: impl AsRef<Path>) -> Result<()> {
    // Connect to Docker daemon
    let docker =
        Docker::connect_with_local_defaults().context("Failed to connect to Docker daemon")?;

    // Read and parse docker-compose.yaml to get project name
    let compose_content =
        fs::read_to_string(compose_file.as_ref()).context("Failed to read docker-compose.yaml")?;
    let docker_compose: ComposeConfig =
        serde_yaml2::from_str(&compose_content).context("Failed to parse docker-compose.yaml")?;

    // Get current project name from compose file or directory name
    let project_name = match docker_compose.name {
        Some(name) => name,
        None => get_project_name(compose_file)?,
    };

    // List all containers
    let options = ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };

    let containers = docker
        .list_containers(Some(options))
        .await
        .context("Failed to list containers")?;

    // Find and remove orphaned containers
    for container in containers {
        let Some(labels) = container.labels else {
            continue;
        };

        // Check if container belongs to current project
        let Some(container_project) = labels.get("com.docker.compose.project") else {
            continue;
        };

        if container_project != &project_name {
            continue;
        }
        // Check if service still exists in compose file
        let Some(service_name) = labels.get("com.docker.compose.service") else {
            continue;
        };
        if docker_compose.services.contains_key(service_name) {
            continue;
        }
        // Service no longer exists in compose file, remove the container
        let Some(container_id) = container.id else {
            continue;
        };

        println!("Removing orphaned container {service_name} {container_id}");
        docker
            .remove_container(
                &container_id,
                Some(RemoveContainerOptions {
                    v: true,
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .with_context(|| format!("Failed to remove container {}", container_id))?;
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

    let cli = Cli::parse();

    match cli.command {
        Commands::Report => cmd_report()?,
        Commands::Quote => cmd_quote()?,
        Commands::Show => cmd_show_mrs()?,
        Commands::Extend(extend_args) => {
            cmd_extend(extend_args)?;
        }
        Commands::Hex(hex_args) => {
            cmd_hex(hex_args)?;
        }
        Commands::GenRaCert(args) => {
            cmd_gen_ra_cert(args)?;
        }
        Commands::Rand(rand_args) => {
            cmd_rand(rand_args)?;
        }
        Commands::GenCaCert(args) => {
            cmd_gen_ca_cert(args)?;
        }
        Commands::GenAppKeys(args) => {
            cmd_gen_app_keys(args)?;
        }
        Commands::Setup(args) => {
            cmd_sys_setup(args).await?;
        }
        Commands::NotifyHost(args) => {
            cmd_notify_host(args).await?;
        }
        Commands::RemoveOrphans(args) => {
            cmd_remove_orphans(args.compose).await?;
        }
    }

    Ok(())
}
