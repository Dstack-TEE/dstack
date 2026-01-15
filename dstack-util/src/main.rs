// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dstack_attest::emit_runtime_event;
use dstack_types::{KeyProvider, KeyProviderKind};
use fs_err as fs;
use getrandom::fill as getrandom;
use host_api::HostApi;
use k256::schnorr::SigningKey;
use ra_rpc::Attestation;
use ra_tls::{
    attestation::QuoteContentType,
    cert::generate_ra_cert,
    kdf::{derive_ecdsa_key, derive_ecdsa_key_pair_from_bytes},
    rcgen::KeyPair,
};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
use system_setup::{cmd_gateway_refresh, cmd_sys_setup, GatewayRefreshArgs, SetupArgs};
use tdx_attest as att;
use utils::AppKeys;

mod crypto;
mod docker_compose;
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
    /// Generate a TDX quote given report data from stdin
    Quote,
    /// Get TDX event logs
    Eventlog,
    /// Extend RTMRs
    Extend(ExtendArgs),
    /// Show the current RTMR state
    Show,
    /// Replay event log and show calculated IMR/RTMR values
    ReplayImr,
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
    /// Refresh the dstack gateway configuration
    GatewayRefresh(GatewayRefreshArgs),
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

    /// show what would be removed without actually removing
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Offline mode: operate without Docker daemon by directly reading Docker data directory
    #[arg(long)]
    no_dockerd: bool,

    /// Docker data root directory for offline mode (default: /var/lib/docker)
    #[arg(short = 'd', long, default_value = "/var/lib/docker")]
    docker_root: String,
}

fn cmd_quote() -> Result<()> {
    let mut report_data = [0; 64];
    io::stdin()
        .read_exact(&mut report_data)
        .context("Failed to read report data")?;
    let quote = att::get_quote(&report_data).context("Failed to get quote")?;
    io::stdout()
        .write_all(&quote)
        .context("Failed to write quote")?;
    Ok(())
}

fn cmd_eventlog() -> Result<()> {
    let event_logs = cc_eventlog::tdx::read_event_log().context("Failed to read event logs")?;
    serde_json::to_writer_pretty(io::stdout(), &event_logs)
        .context("Failed to write event logs")?;
    Ok(())
}

fn hex_decode(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str.trim_start_matches("0x")).context("Invalid hex string")
}

fn cmd_extend(extend_args: ExtendArgs) -> Result<()> {
    let payload = hex_decode(&extend_args.payload).context("Failed to decode payload")?;
    emit_runtime_event(&extend_args.event, &payload).context("Failed to extend RTMR")
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

fn cmd_show_mrs() -> Result<()> {
    let attestation =
        ra_tls::attestation::Attestation::local().context("Failed to get attestation")?;
    let app_info = attestation
        .decode_app_info(false)
        .context("Failed to decode app info")?;
    serde_json::to_writer_pretty(io::stdout(), &app_info).context("Failed to write app info")?;
    println!();
    Ok(())
}

fn cmd_replay_imr() -> Result<()> {
    use sha2::Digest;

    println!("=== Event Log Replay: Calculated IMR/RTMR Values ===\n");

    // Read and replay event logs
    let event_logs = att::eventlog::tdx::read_event_log().context("Failed to read event logs")?;

    println!("Total events: {}", event_logs.len());

    // Count events per IMR
    let mut imr_counts = [0u32; 4];
    for event in &event_logs {
        if event.imr < 4 {
            imr_counts[event.imr as usize] += 1;
        }
    }

    println!("Event distribution:");
    for (idx, count) in imr_counts.iter().enumerate() {
        println!("  IMR {}: {} events", idx, count);
    }
    println!();

    // Replay event logs to calculate IMR/RTMR values
    println!("Replaying event log...");
    let mut rtmrs: [[u8; 48]; 4] = [[0u8; 48]; 4];

    for event in &event_logs {
        if event.imr < 4 {
            let mut hasher = sha2::Sha384::new();
            hasher.update(rtmrs[event.imr as usize]);
            hasher.update(event.digest());
            rtmrs[event.imr as usize] = hasher.finalize().into();
        }
    }

    println!("\nCalculated IMR/RTMR values from event log replay:\n");
    println!("IMR 0 (CCEL) → {}", hex::encode(rtmrs[0]));
    println!("IMR 1 (CCEL) → {}", hex::encode(rtmrs[1]));
    println!("IMR 2 (CCEL) → {}", hex::encode(rtmrs[2]));
    println!("IMR 3 (CCEL) → {}", hex::encode(rtmrs[3]));

    println!("\n========================================");
    println!("Note: These are the calculated values from replaying the CCEL event log.");
    println!("The mapping between CCEL IMR indices and TDX RTMR indices may vary");
    println!("depending on the platform implementation.");

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
    let attestation = Attestation::quote(&report_data)
        .context("Failed to get attestation")?
        .into_versioned();

    let req = CertRequest::builder()
        .subject("App Root CA")
        .attestation(&attestation)
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
    let key_provider = KeyProvider::None {
        key: key.serialize_pem(),
    };
    let app_keys = make_app_keys(&key, &disk_key, &k256_key, args.ca_level, key_provider)?;
    let app_keys = serde_json::to_string(&app_keys).context("Failed to serialize app keys")?;
    fs::write(&args.output, app_keys).context("Failed to write app keys")?;
    Ok(())
}

fn gen_app_keys_from_seed(
    seed: &[u8],
    provider: KeyProviderKind,
    mr: Option<Vec<u8>>,
) -> Result<AppKeys> {
    let key = derive_ecdsa_key_pair_from_bytes(seed, &["app-key".as_bytes()])?;
    let disk_key = derive_ecdsa_key_pair_from_bytes(seed, &["app-disk-key".as_bytes()])?;
    let k256_key = derive_ecdsa_key(seed, &["app-k256-key".as_bytes()], 32)?;
    let k256_key = SigningKey::from_bytes(&k256_key).context("Failed to parse k256 key")?;
    let key_provider = match provider {
        KeyProviderKind::None => KeyProvider::None {
            key: key.serialize_pem(),
        },
        KeyProviderKind::Local => KeyProvider::Local {
            mr: mr.context("Missing MR for local key provider")?,
            key: key.serialize_pem(),
        },
        KeyProviderKind::Tpm => KeyProvider::Tpm {
            key: key.serialize_pem(),
            pubkey: key.public_key_der(),
        },
        KeyProviderKind::Kms => {
            anyhow::bail!("KMS keys must be fetched from the KMS server")
        }
    };
    make_app_keys(&key, &disk_key, &k256_key, 1, key_provider)
}

fn make_app_keys(
    app_key: &KeyPair,
    disk_key: &KeyPair,
    k256_key: &SigningKey,
    ca_level: u8,
    key_provider: KeyProvider,
) -> Result<AppKeys> {
    use ra_tls::cert::CertRequest;
    let pubkey = app_key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let attestation = Attestation::quote(&report_data)
        .context("Failed to get attestation")?
        .into_versioned();
    let req = CertRequest::builder()
        .subject("App Root Cert")
        .attestation(&attestation)
        .key(app_key)
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
        key_provider,
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

#[tokio::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Quote => cmd_quote()?,
        Commands::Eventlog => cmd_eventlog()?,
        Commands::Show => cmd_show_mrs()?,
        Commands::ReplayImr => cmd_replay_imr()?,
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
        Commands::GatewayRefresh(args) => {
            cmd_gateway_refresh(args).await?;
        }
        Commands::NotifyHost(args) => {
            cmd_notify_host(args).await?;
        }
        Commands::RemoveOrphans(args) => {
            if args.no_dockerd {
                docker_compose::remove_orphans_direct(
                    args.compose,
                    args.docker_root,
                    args.dry_run,
                )?;
            } else {
                docker_compose::remove_orphans(args.compose, args.dry_run).await?;
            }
        }
    }

    Ok(())
}
