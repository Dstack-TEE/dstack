// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

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
    attestation::{QuoteContentType, VersionedAttestation},
    cert::{generate_ra_cert, generate_ra_cert_with_app_id},
    kdf::{derive_key, derive_p256_key_pair_from_bytes},
    rcgen::KeyPair,
};
use scale::Encode;
use std::path::Path;
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
    /// Perform vTPM attestation (for GCP TEE instances)
    VtpmAttest(VtpmAttestArgs),
    /// Generate a TPM quote
    TpmQuote(TpmQuoteArgs),
    /// Verify a TPM quote
    TpmVerify(TpmVerifyArgs),
    QuoteReport(QuoteReportArgs),
    /// Generate a versioned attestation for simulator use
    Attest(AttestArgs),
    /// Show size breakdown for a versioned attestation file
    AttestInfo(AttestInfoArgs),
    /// Dump a versioned attestation as JSON
    AttestJson(AttestJsonArgs),
    /// Strip attestation for certificate embedding
    AttestStrip(AttestStripArgs),
    /// Get app keys from a KMS server
    GetKeys(GetKeysArgs),
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

#[derive(Parser)]
/// Perform vTPM attestation
struct VtpmAttestArgs {
    /// path to Root CA certificate (PEM format)
    #[arg(long)]
    root_ca: PathBuf,

    /// nonce for replay protection
    #[arg(long)]
    nonce: String,

    /// expected OS image SHA256 hash (optional)
    #[arg(long)]
    expected_os_hash: Option<String>,

    /// key algorithm (rsa or ecc, default: rsa)
    #[arg(long, default_value = "rsa")]
    key_algo: String,

    /// output format (json or text, default: text)
    #[arg(long, default_value = "text")]
    format: String,
}

#[derive(Parser)]
/// Generate a TPM quote
struct TpmQuoteArgs {
    /// qualifying data (hex encoded, default: 32 zeros)
    #[arg(short, long)]
    data: Option<String>,

    /// output file (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// key algorithm (auto, ecc, or rsa; default: auto)
    #[arg(short = 'k', long, default_value = "auto")]
    key_algo: String,

    /// The hash algorithm to use (default: none)
    #[arg(short = 'H', long, default_value = "none")]
    hash_algo: String,
}

#[derive(Parser)]
/// Verify a TPM quote
struct TpmVerifyArgs {
    /// path to Root CA certificate (PEM format)
    #[arg(long)]
    root_ca: PathBuf,

    /// path to TPM quote JSON file
    #[arg(short, long)]
    quote: PathBuf,
}

#[derive(Parser)]
struct QuoteReportArgs {
    #[arg(long)]
    report_data: Option<String>,

    #[arg(long, default_value = "/dstack/.host-shared/.sys-config.json")]
    sys_config: PathBuf,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    debug: bool,
}

#[derive(Parser)]
struct AttestArgs {
    /// report data in hex (max 64 bytes)
    #[arg(long)]
    report_data: Option<String>,

    /// app id (20 bytes in hex) - optional
    #[arg(long)]
    app_id: Option<String>,

    /// output file (default: attestation.bin)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// hex encode output
    #[arg(long, default_value_t = false)]
    hex: bool,
}

#[derive(Parser)]
struct AttestInfoArgs {
    /// input file (default: attestation.bin)
    #[arg(short, long)]
    input: Option<PathBuf>,
}

#[derive(Parser)]
struct AttestJsonArgs {
    /// input file (default: attestation.bin)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// output file (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Parser)]
struct AttestStripArgs {
    /// input file (default: attestation.bin)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// output file (default: attestation.strip.bin)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Parser)]
/// Get app keys from a KMS server
struct GetKeysArgs {
    /// KMS server URL (e.g., https://kms.example.com)
    #[arg(short, long)]
    kms_url: String,

    /// Application ID (20 bytes in hex) - optional
    #[arg(long)]
    app_id: Option<String>,

    /// Output file path (default: stdout as JSON)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Root CA certificate (PEM format) to pin for TLS verification.
    /// If not provided, TLS certificate verification is skipped for the initial connection.
    #[arg(long)]
    root_ca: Option<PathBuf>,
}

fn pad64(data: &[u8]) -> Result<[u8; 64]> {
    if data.len() > 64 {
        anyhow::bail!("report_data must be at most 64 bytes");
    }
    let mut out = [0u8; 64];
    out[..data.len()].copy_from_slice(data);
    Ok(out)
}

fn cmd_quote_report(args: QuoteReportArgs) -> Result<()> {
    #[derive(serde::Serialize)]
    struct VerificationRequestJson {
        pub attestation: String,
    }

    let report_data = match args.report_data {
        Some(hex_data) => {
            pad64(&hex_decode(&hex_data).context("Failed to decode report_data hex")?)?
        }
        None => [0u8; 64],
    };
    let attestation = Attestation::quote(&report_data).context("Failed to get attestation")?;
    let request = VerificationRequestJson {
        attestation: hex::encode(attestation.into_versioned().to_scale()?),
    };

    let json =
        serde_json::to_string_pretty(&request).context("Failed to serialize request JSON")?;
    if let Some(output_path) = args.output {
        fs::write(&output_path, json).context("Failed to write quote report")?;
    } else {
        println!("{json}");
    }
    Ok(())
}

fn decode_app_id(hex_str: Option<&str>) -> Result<Option<[u8; 20]>> {
    let Some(hex_str) = hex_str else {
        return Ok(None);
    };
    let bytes = hex_decode(hex_str).context("Invalid app_id hex string")?;
    if bytes.len() != 20 {
        anyhow::bail!("app_id must be exactly 20 bytes (40 hex characters)");
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(Some(arr))
}

fn cmd_attest(args: AttestArgs) -> Result<()> {
    let report_data = match args.report_data {
        Some(hex_data) => {
            pad64(&hex_decode(&hex_data).context("Failed to decode report_data hex")?)?
        }
        None => [0u8; 64],
    };
    let app_id = decode_app_id(args.app_id.as_deref())?;
    let attestation = Attestation::quote_with_app_id(&report_data, app_id)
        .context("Failed to get attestation")?;
    let attestation = attestation.into_versioned().to_scale()?;

    if args.hex {
        let encoded = hex::encode(&attestation);
        if let Some(output) = args.output {
            fs::write(&output, encoded).context("Failed to write attestation hex")?;
        } else {
            println!("{encoded}");
        }
        return Ok(());
    }

    let output = args
        .output
        .unwrap_or_else(|| PathBuf::from("attestation.bin"));
    fs::write(&output, &attestation).context("Failed to write attestation sample")?;
    Ok(())
}

fn cmd_attest_info(args: AttestInfoArgs) -> Result<()> {
    let input = args
        .input
        .unwrap_or_else(|| PathBuf::from("attestation.bin"));
    let data = fs::read(&input).context("Failed to read attestation file")?;
    let attestation =
        VersionedAttestation::from_scale(&data).context("Failed to decode attestation")?;

    println!("file: {}", input.display());
    println!("total_bytes: {}", data.len());

    match attestation {
        VersionedAttestation::V0 { attestation } => {
            println!("version: V0");
            println!("mode: {:?}", attestation.quote.mode());
            println!("config_bytes: {}", attestation.config.len());
            match attestation.tdx_quote() {
                Some(tdx) => {
                    let event_log_json = serde_json::to_vec(&tdx.event_log)
                        .context("Failed to serialize event log")?;
                    println!("tdx_quote_bytes: {}", tdx.quote.len());
                    println!("event_log_entries: {}", tdx.event_log.len());
                    println!("event_log_json_bytes: {}", event_log_json.len());
                }

                None => {
                    println!("tdx_quote_bytes: 0");
                    println!("event_log_entries: 0");
                    println!("event_log_json_bytes: 0");
                }
            }
            match attestation.tpm_quote() {
                Some(tpm) => {
                    let tpm_bytes = tpm.encode();
                    println!("tpm_quote_bytes: {}", tpm_bytes.len());
                }
                None => println!("tpm_quote_bytes: 0"),
            }
        }
        VersionedAttestation::V1 { attestation } => {
            println!("version: V1");
            println!("platform: {:?}", attestation.platform);
            println!("stack: {:?}", attestation.stack);
        }
    }

    Ok(())
}

fn cmd_attest_json(args: AttestJsonArgs) -> Result<()> {
    let input = args
        .input
        .unwrap_or_else(|| PathBuf::from("attestation.bin"));
    let data = fs::read(&input).context("Failed to read attestation file")?;
    let attestation =
        VersionedAttestation::from_scale(&data).context("Failed to decode attestation")?;

    let json = match attestation {
        VersionedAttestation::V0 { attestation } => {
            let mode = attestation.quote.mode().as_str();
            let tdx_quote = match attestation.tdx_quote() {
                Some(tdx) => serde_json::json!({
                    "quote": hex::encode(&tdx.quote),
                    "event_log": tdx.event_log,
                }),
                None => serde_json::Value::Null,
            };
            let tpm_quote = match attestation.tpm_quote() {
                Some(tpm) => serde_json::to_value(tpm).context("Failed to serialize TPM quote")?,
                None => serde_json::Value::Null,
            };

            serde_json::json!({
                "version": "V0",
                "mode": mode,
                "config": attestation.config,
                "tdx_quote": tdx_quote,
                "tpm_quote": tpm_quote,
            })
        }
        VersionedAttestation::V1 { attestation } => {
            serde_json::to_value(&attestation).context("Failed to serialize V1 attestation")?
        }
    };

    let output = serde_json::to_string_pretty(&json).context("Failed to serialize JSON")?;
    if let Some(path) = args.output {
        fs::write(&path, output).context("Failed to write JSON output")?;
    } else {
        println!("{output}");
    }
    Ok(())
}

fn cmd_attest_strip(args: AttestStripArgs) -> Result<()> {
    let input = args
        .input
        .unwrap_or_else(|| PathBuf::from("attestation.bin"));
    let data = fs::read(&input).context("Failed to read attestation file")?;
    let attestation =
        VersionedAttestation::from_scale(&data).context("Failed to decode attestation")?;
    let stripped = attestation.into_stripped();
    let output = args
        .output
        .unwrap_or_else(|| PathBuf::from("attestation.strip.bin"));
    fs::write(&output, stripped.to_scale()?).context("Failed to write stripped attestation")?;
    Ok(())
}

async fn cmd_get_keys(args: GetKeysArgs) -> Result<()> {
    use dstack_kms_rpc::kms_client::KmsClient;
    use ra_rpc::client::RaClientConfig;

    let kms_url = if args.kms_url.ends_with("/prpc") {
        args.kms_url.clone()
    } else {
        format!("{}/prpc", args.kms_url.trim_end_matches('/'))
    };

    // Load root CA if provided for TLS pinning
    let root_ca_pem = if let Some(root_ca_path) = &args.root_ca {
        let pem = fs::read_to_string(root_ca_path)
            .with_context(|| format!("failed to read root CA from {}", root_ca_path.display()))?;
        Some(pem)
    } else {
        None
    };

    // Step 1: Get temporary CA certificate
    eprintln!("Connecting to KMS: {kms_url}");
    let tls_no_check = root_ca_pem.is_none();
    if tls_no_check {
        eprintln!("Warning: no --root-ca provided, TLS certificate verification is disabled for initial connection");
    }
    let tmp_ca = {
        let client = RaClientConfig::builder()
            .remote_uri(kms_url.clone())
            .tls_no_check(tls_no_check)
            .tls_built_in_root_certs(false)
            .maybe_tls_ca_cert(root_ca_pem.clone())
            .build()
            .into_client()
            .context("failed to create client")?;
        let kms_client = KmsClient::new(client);
        kms_client
            .get_temp_ca_cert()
            .await
            .context("Failed to get temp CA cert")?
    };

    // Step 2: Generate RA-TLS client certificate
    let app_id = decode_app_id(args.app_id.as_deref())?;
    let cert_pair = generate_ra_cert_with_app_id(
        tmp_ca.temp_ca_cert.clone(),
        tmp_ca.temp_ca_key.clone(),
        app_id,
    )
    .context("Failed to generate RA cert")?;

    // Step 3: Create authenticated client and request app keys
    let ra_client = RaClientConfig::builder()
        .tls_no_check(false)
        .tls_built_in_root_certs(false)
        .remote_uri(kms_url.clone())
        .tls_client_cert(cert_pair.cert_pem)
        .tls_client_key(cert_pair.key_pem)
        .tls_ca_cert(tmp_ca.ca_cert.clone())
        .build()
        .into_client()
        .context("Failed to create RA client")?;

    let kms_client = KmsClient::new(ra_client);
    let response = kms_client
        .get_app_key(dstack_kms_rpc::GetAppKeyRequest {
            api_version: 1,
            vm_config: "".to_string(),
        })
        .await
        .context("Failed to get app key")?;

    // Step 4: Build AppKeys structure
    let (_, ca_pem) = x509_parser::pem::parse_x509_pem(tmp_ca.ca_cert.as_bytes())
        .context("Failed to parse CA cert")?;
    let x509 = ca_pem.parse_x509().context("Failed to parse CA cert")?;
    let root_pubkey = x509.public_key().raw.to_vec();

    let keys = utils::AppKeys {
        ca_cert: tmp_ca.ca_cert,
        disk_crypt_key: response.disk_crypt_key,
        env_crypt_key: response.env_crypt_key,
        k256_key: response.k256_key,
        k256_signature: response.k256_signature,
        gateway_app_id: response.gateway_app_id,
        key_provider: KeyProvider::Kms {
            url: kms_url,
            pubkey: root_pubkey,
            tmp_ca_key: tmp_ca.temp_ca_key,
            tmp_ca_cert: tmp_ca.temp_ca_cert,
        },
    };

    // Step 5: Output result
    let json = serde_json::to_string_pretty(&keys).context("Failed to serialize app keys")?;
    if let Some(output_path) = args.output {
        fs::write(&output_path, &json).context("Failed to write app keys")?;
        eprintln!("App keys written to: {}", output_path.display());
    } else {
        println!("{json}");
    }

    Ok(())
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
        .into_v1()
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
    let key = derive_p256_key_pair_from_bytes(seed, &["app-key".as_bytes()])?;
    let disk_key = derive_p256_key_pair_from_bytes(seed, &["app-disk-key".as_bytes()])?;
    let k256_key = derive_key(seed, &["app-k256-key".as_bytes()], 32)?;
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

fn cmd_vtpm_attest(args: VtpmAttestArgs) -> Result<()> {
    use cmd_lib::run_cmd;
    use serde::Serialize;

    #[derive(Serialize)]
    struct AttestationResult {
        success: bool,
        ek_cert_verified: bool,
        quote_verified: bool,
        os_image_verified: Option<bool>,
        nonce: String,
        key_algorithm: String,
        error: Option<String>,
    }

    // verify root CA file exists
    if !args.root_ca.exists() {
        anyhow::bail!("root CA file not found: {:?}", args.root_ca);
    }

    // verify key algorithm
    let (ek_algo, ak_algo, ak_scheme, algo_name) = match args.key_algo.to_lowercase().as_str() {
        "rsa" => ("rsa", "rsa", "rsassa", "RSA-2048"),
        "ecc" | "ecdsa" => ("ecc", "ecc", "ecdsa", "ECC P-256"),
        _ => anyhow::bail!(
            "invalid key algorithm: {}. Use 'rsa' or 'ecc'",
            args.key_algo
        ),
    };

    let mut result = AttestationResult {
        success: false,
        ek_cert_verified: false,
        quote_verified: false,
        os_image_verified: None,
        nonce: args.nonce.clone(),
        key_algorithm: algo_name.to_string(),
        error: None,
    };

    let attestation_result = (|| -> Result<()> {
        if args.format == "text" {
            println!("=== vTPM Attestation ===");
            println!("Root CA: {:?}", args.root_ca);
            println!("Nonce: {}", args.nonce);
            println!("Key Algorithm: {}", algo_name);
            println!();
        }

        // step 1: extract EK certificate
        if args.format == "text" {
            println!("[1/7] extracting EK certificate...");
        }
        run_cmd! {
            tpm2_nvread -o /tmp/ek_cert.der 0x1c00002 2>/dev/null;
            openssl x509 -inform DER -in /tmp/ek_cert.der -out /tmp/ek_cert.pem 2>/dev/null;
        }
        .context("failed to extract EK certificate")?;

        // step 2: extract intermediate CA URL
        if args.format == "text" {
            println!("[2/7] downloading intermediate CA...");
        }
        let ica_url_output = std::process::Command::new("openssl")
            .args(["x509", "-in", "/tmp/ek_cert.pem", "-noout", "-text"])
            .output()
            .context("failed to read EK cert")?;
        let ica_text = String::from_utf8_lossy(&ica_url_output.stdout);
        let ica_url = ica_text
            .lines()
            .find(|l| l.contains("CA Issuers") && l.contains("URI:"))
            .and_then(|l| l.split("URI:").nth(1))
            .map(|s| s.trim())
            .context("failed to find Intermediate CA URL")?;

        run_cmd! {
            curl -s -o /tmp/intermediate_ca.crt $ica_url;
        }
        .context("failed to download intermediate CA")?;

        // try DER first, then PEM
        let convert_result = run_cmd! {
            openssl x509 -inform DER -in /tmp/intermediate_ca.crt -outform PEM -out /tmp/intermediate_ca.pem 2>/dev/null;
        };
        if convert_result.is_err() {
            run_cmd! {
                openssl x509 -inform PEM -in /tmp/intermediate_ca.crt -outform PEM -out /tmp/intermediate_ca.pem 2>/dev/null;
            }
            .context("failed to convert intermediate CA")?;
        }

        // step 3: verify intermediate CA
        if args.format == "text" {
            println!("[3/7] verifying certificate chain...");
        }
        let root_ca_path = args.root_ca.to_str().context("invalid root CA path")?;
        run_cmd! {
            openssl verify -CAfile $root_ca_path /tmp/intermediate_ca.pem >/dev/null 2>&1;
        }
        .context("intermediate CA verification failed")?;

        // step 4: verify EK certificate
        run_cmd! {
            cat /tmp/intermediate_ca.pem $root_ca_path > /tmp/ca_chain.pem;
            openssl verify -CAfile /tmp/ca_chain.pem /tmp/ek_cert.pem >/dev/null 2>&1;
        }
        .context("EK certificate verification failed")?;
        result.ek_cert_verified = true;

        // step 5: create AK
        if args.format == "text" {
            println!("[4/7] creating attestation key ({})...", algo_name);
        }
        run_cmd! {
            tpm2_createek -c /tmp/ek.ctx -G $ek_algo -u /tmp/ek.pub >/dev/null 2>&1;
            tpm2_createak -C /tmp/ek.ctx -c /tmp/ak.ctx -G $ak_algo -g sha256 -s $ak_scheme -u /tmp/ak.pub -n /tmp/ak.name >/dev/null 2>&1;
        }
        .context("failed to create attestation key")?;

        // step 6: generate quote
        if args.format == "text" {
            println!("[5/7] generating TPM quote...");
        }
        let nonce = &args.nonce;
        run_cmd! {
            echo -n $nonce > /tmp/nonce.bin;
            tpm2_quote -c /tmp/ak.ctx -l sha256:0,1,2,3,4,5,6,7,8,9,10,14 -q /tmp/nonce.bin -m /tmp/quote.msg -s /tmp/quote.sig -o /tmp/quote.pcr -g sha256 >/dev/null 2>&1;
        }
        .context("failed to generate quote")?;

        // step 7: verify quote
        if args.format == "text" {
            println!("[6/7] verifying quote signature...");
        }
        run_cmd! {
            tpm2_checkquote -u /tmp/ak.pub -m /tmp/quote.msg -s /tmp/quote.sig -f /tmp/quote.pcr -g sha256 -q /tmp/nonce.bin >/dev/null 2>&1;
        }
        .context("quote verification failed")?;
        result.quote_verified = true;

        // step 8: verify OS image (optional)
        if let Some(expected_hash) = &args.expected_os_hash {
            if args.format == "text" {
                println!("[7/7] verifying OS image...");
            }
            let tpm_eventlog_path = "/sys/kernel/security/tpm0/binary_bios_measurements";
            if Path::new(tpm_eventlog_path).exists() {
                let _ = run_cmd! {
                    tpm2_eventlog $tpm_eventlog_path > /tmp/eventlog.yaml 2>/dev/null;
                };

                let eventlog = fs::read_to_string("/tmp/eventlog.yaml").unwrap_or_default();
                if eventlog.contains(expected_hash) {
                    result.os_image_verified = Some(true);
                } else {
                    result.os_image_verified = Some(false);
                    anyhow::bail!("OS image hash mismatch");
                }
            }
        }

        result.success = true;
        Ok(())
    })();

    if let Err(e) = attestation_result {
        result.error = Some(format!("{:#}", e));
    }

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!();
        println!("=== Attestation Result ===");
        println!(
            "  EK Certificate Chain: {}",
            if result.ek_cert_verified {
                "✓ VERIFIED"
            } else {
                "✗ FAILED"
            }
        );
        println!(
            "  TPM Quote: {}",
            if result.quote_verified {
                "✓ VERIFIED"
            } else {
                "✗ FAILED"
            }
        );
        if let Some(os_verified) = result.os_image_verified {
            println!(
                "  OS Image: {}",
                if os_verified {
                    "✓ VERIFIED"
                } else {
                    "✗ MISMATCH"
                }
            );
        }
        println!();
        if result.success {
            println!("🎉 ATTESTATION PASSED");
        } else {
            println!("❌ ATTESTATION FAILED");
            if let Some(error) = &result.error {
                println!("Error: {}", error);
            }
            anyhow::bail!("attestation failed");
        }
    }

    Ok(())
}

fn cmd_tpm_quote(args: TpmQuoteArgs) -> Result<()> {
    let data = if let Some(hex_data) = args.data {
        let decoded = hex_decode(&hex_data).context("Failed to decode hex data")?;
        if decoded.len() > 64 {
            anyhow::bail!("Qualifying data must be at most 64 bytes");
        }
        decoded
    } else {
        vec![0u8; 32] // TPM 2.0 max qualifying data is 32 bytes
    };

    // Parse key algorithm
    let key_algo = args
        .key_algo
        .parse::<tpm_attest::KeyAlgorithm>()
        .context("Failed to parse key algorithm")?;

    let qualifying_data: [u8; 32] = match args.hash_algo.as_str() {
        "none" => data
            .try_into()
            .ok()
            .context("qualifying data must be 32 bytes")?,
        "sha256" => ez_hash::sha256(&data),
        _ => {
            anyhow::bail!("Unsupported hash algorithm");
        }
    };

    let tpm = tpm_attest::TpmContext::open(None).context("Failed to open TPM context")?;
    let pcr_selection = tpm_attest::dstack_pcr_policy();
    let tpm_quote = tpm
        .create_quote_with_algo(&qualifying_data, &pcr_selection, key_algo)
        .context("Failed to create TPM quote")?;

    let quote_json =
        serde_json::to_string_pretty(&tpm_quote).context("Failed to serialize TPM quote")?;

    if let Some(output_path) = args.output {
        fs::write(&output_path, quote_json).context("Failed to write quote to file")?;
        eprintln!("TPM quote written to: {:?}", output_path);
    } else {
        println!("{}", quote_json);
    }

    Ok(())
}

async fn cmd_tpm_verify(args: TpmVerifyArgs) -> Result<()> {
    let root_ca_pem = fs::read_to_string(&args.root_ca).context("Failed to read root CA")?;
    let quote_json = fs::read_to_string(&args.quote).context("Failed to read quote file")?;
    let tpm_quote: tpm_attest::TpmQuote =
        serde_json::from_str(&quote_json).context("Failed to parse quote JSON")?;

    println!("=== TPM Quote Verification (dcap-qvl architecture) ===");
    println!("Root CA: {:?}", args.root_ca);
    println!("Quote file: {:?}", args.quote);
    println!();

    // Step 1: Get collateral (certificates + CRLs)
    println!("[Step 1] Fetching quote collateral (certificates + CRLs)...");
    let collateral = tpm_qvl::get_collateral(&tpm_quote, &root_ca_pem)
        .await
        .context("Failed to get collateral")?;
    let crl_count = collateral.crls.len()
        + if collateral.root_ca_crl.is_some() {
            1
        } else {
            0
        };
    println!("  ✓ Collateral fetched: {} CRLs downloaded", crl_count);
    println!();

    // Step 2: Verify quote with conditional CRL checking
    println!("[Step 2] Verifying quote (CRL verification if CRL DP present)...");

    match tpm_qvl::verify::verify_quote_with_ca(&tpm_quote, &collateral, &root_ca_pem) {
        Ok(_) => {
            // Success - print simple success message
            println!();
            let crl_count = collateral.crls.len()
                + if collateral.root_ca_crl.is_some() {
                    1
                } else {
                    0
                };
            if crl_count == 0 {
                println!("🎉 VERIFICATION PASSED (no CRLs available)");
            } else {
                println!(
                    "🎉 VERIFICATION PASSED (with {} CRL(s) verified)",
                    crl_count
                );
            }
            Ok(())
        }
        Err(verification_result) => {
            // Failure - print detailed status
            println!();
            println!("=== Verification Result ===");
            println!(
                "  AK Certificate Chain (webpki + CRL): {}",
                if verification_result.status.ak_verified {
                    "✓ VERIFIED"
                } else {
                    "✗ FAILED"
                }
            );
            println!(
                "  Quote Signature: {}",
                if verification_result.status.signature_verified {
                    "✓ VERIFIED"
                } else {
                    "✗ FAILED"
                }
            );
            println!(
                "  PCR Values: {}",
                if verification_result.status.pcr_verified {
                    "✓ VERIFIED"
                } else {
                    "✗ FAILED"
                }
            );
            println!("  Error: {}", verification_result.error);
            println!();
            anyhow::bail!("Verification failed")
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
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
        Commands::VtpmAttest(args) => {
            cmd_vtpm_attest(args)?;
        }
        Commands::TpmQuote(args) => {
            cmd_tpm_quote(args)?;
        }
        Commands::TpmVerify(args) => {
            cmd_tpm_verify(args).await?;
        }
        Commands::QuoteReport(args) => {
            cmd_quote_report(args)?;
        }
        Commands::Attest(args) => {
            cmd_attest(args)?;
        }
        Commands::AttestInfo(args) => {
            cmd_attest_info(args)?;
        }
        Commands::AttestJson(args) => {
            cmd_attest_json(args)?;
        }
        Commands::AttestStrip(args) => {
            cmd_attest_strip(args)?;
        }
        Commands::GetKeys(args) => {
            cmd_get_keys(args).await?;
        }
    }

    Ok(())
}
