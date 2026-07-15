// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use dstack_verifier::{
    CvmVerifier, VerificationDetails, VerificationRequest, VerificationResponse,
};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use rocket::{fairing::AdHoc, get, post, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "dstack-verifier")]
#[command(about = "HTTP server providing CVM verification services")]
struct Cli {
    #[arg(short, long, default_value = "dstack-verifier.toml")]
    config: String,

    /// Oneshot mode: verify a single report JSON file and exit
    #[arg(long, value_name = "FILE")]
    verify: Option<String>,

    /// Oneshot mode: verify a DER or PEM RA-TLS certificate and exit
    #[arg(long, value_name = "FILE")]
    verify_cert: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub address: String,
    pub port: u16,
    pub image_cache_dir: String,
    pub pccs_url: Option<String>,
    pub image_download_url: String,
    pub image_download_timeout_secs: u64,
}

#[post("/verify", data = "<request>")]
async fn verify_cvm(
    verifier: &State<Arc<CvmVerifier>>,
    request: Json<VerificationRequest>,
) -> Json<VerificationResponse> {
    match verifier.verify(request.into_inner()).await {
        Ok(response) => Json(response),
        Err(e) => {
            error!("Verification failed: {:?}", e);
            Json(VerificationResponse {
                is_valid: false,
                details: VerificationDetails::default(),
                reason: Some(format!("Internal error: {}", e)),
            })
        }
    }
}

#[get("/health")]
fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "dstack-verifier"
    }))
}

async fn run_oneshot(file_path: &str, config: &Config) -> anyhow::Result<()> {
    use std::fs;

    info!("Running in oneshot mode for file: {}", file_path);

    // Read the JSON file
    let content = fs::read_to_string(file_path)
        .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", file_path, e))?;

    // Parse as VerificationRequest
    let request: VerificationRequest = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse JSON: {}", e))?;

    // Create verifier
    let verifier = CvmVerifier::new(
        config.image_cache_dir.clone(),
        config.image_download_url.clone(),
        std::time::Duration::from_secs(config.image_download_timeout_secs),
        config.pccs_url.clone(),
    );

    // Run verification
    info!("Starting verification...");
    let response = verifier.verify(request).await?;

    // Persist response next to the input file for convenience
    let output_path = format!("{file_path}.verification.json");
    let serialized = serde_json::to_string_pretty(&response)
        .map_err(|e| anyhow::anyhow!("Failed to encode verification result: {}", e))?;
    fs::write(&output_path, serialized).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write verification result to {}: {}",
            output_path,
            e
        )
    })?;
    info!("Stored verification result at {}", output_path);

    // Output results
    println!("\n=== Verification Results ===");
    println!("Valid: {}", response.is_valid);
    println!("Quote verified: {}", response.details.quote_verified);
    println!(
        "Event log verified: {}",
        response.details.event_log_verified
    );
    println!(
        "OS image hash verified: {}",
        response.details.os_image_hash_verified
    );
    println!(
        "ACPI tables verified: {}",
        response.details.acpi_tables_verified
    );

    if let Some(tcb_status) = &response.details.tcb_status {
        println!("TCB status: {}", tcb_status);
    }

    if !response.details.advisory_ids.is_empty() {
        println!("Advisory IDs: {:?}", response.details.advisory_ids);
    }

    if let Some(reason) = &response.reason {
        println!("Reason: {}", reason);
    }

    if let Some(report_data) = &response.details.report_data {
        println!("Report data: {}", report_data);
    }

    if let Some(app_info) = &response.details.app_info {
        println!("\n=== App Info ===");
        println!("App ID: {}", hex::encode(&app_info.app_id));
        println!("Instance ID: {}", hex::encode(&app_info.instance_id));
        println!("Compose hash: {}", hex::encode(&app_info.compose_hash));
    }

    // Exit with appropriate code
    if !response.is_valid {
        std::process::exit(1);
    }

    Ok(())
}

async fn run_cert_oneshot(file_path: &str, config: &Config) -> anyhow::Result<()> {
    use std::fs;

    info!(
        "running in certificate oneshot mode for file: {}",
        file_path
    );

    let cert = fs::read(file_path)
        .map_err(|e| anyhow::anyhow!("failed to read certificate {}: {}", file_path, e))?;

    let verified = if cert.starts_with(b"-----BEGIN") {
        ra_tls::attestation::verify_pem(&cert, config.pccs_url.as_deref()).await
    } else {
        ra_tls::attestation::verify_der(&cert, config.pccs_url.as_deref()).await
    }
    .map_err(|e| anyhow::anyhow!("failed to verify RA-TLS certificate: {:#}", e))?;

    let app_info = verified.attestation.decode_app_info(false).ok();
    // Bind the reported os_image_hash to the attested boot measurement. For
    // every platform except TDX legacy this is a self-contained check (no image
    // download); relying parties should only trust `os_image_hash` when
    // `os_image_hash_verified` is true.
    let os_image_hash_verified = verify_cert_os_image_hash(&verified.attestation, config).await;
    let output = serde_json::json!({
        "is_valid": true,
        "details": {
            "endpoint_identity_verified": true,
            "attestation_mode": verified.attestation.quote.mode(),
            "tee_platform": verified.attestation.quote.mode().as_str(),
            "report_data": hex::encode(verified.attestation.report_data),
            "public_key_der": hex::encode(&verified.public_key_der),
            "app_id_extension": verified.app_id.as_ref().map(hex::encode),
            "special_usage": verified.special_usage,
            "app_info_extension_present": verified.app_info.is_some(),
            "app_info": app_info.map(|info| serde_json::json!({
                "app_id": hex::encode(info.app_id),
                "compose_hash": hex::encode(info.compose_hash),
                "instance_id": hex::encode(info.instance_id),
                "device_id": hex::encode(info.device_id),
                "mr_system": hex::encode(info.mr_system),
                "mr_aggregated": hex::encode(info.mr_aggregated),
                "os_image_hash": hex::encode(info.os_image_hash),
                "os_image_hash_verified": os_image_hash_verified,
                "key_provider_info": hex::encode(info.key_provider_info),
            })),
        }
    });

    let output_path = format!("{file_path}.ratls-verification.json");
    fs::write(&output_path, serde_json::to_string_pretty(&output)?).map_err(|e| {
        anyhow::anyhow!(
            "failed to write certificate verification result to {}: {}",
            output_path,
            e
        )
    })?;
    info!("stored certificate verification result at {}", output_path);
    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

/// Verify that an RA-TLS certificate's `os_image_hash` is bound to its attested
/// boot measurement.
///
/// Returns `true` only when the binding checks out. Returns `false` for TDX
/// legacy (whose binding needs an image download that this oneshot mode does not
/// perform) and for any binding failure. Every other platform — AWS NitroTPM,
/// SEV-SNP, Nitro Enclave, GCP TDX, and TDX lite — is verified from
/// self-contained material carried in the attestation, without network access.
async fn verify_cert_os_image_hash(
    attestation: &ra_tls::attestation::VerifiedAttestation,
    config: &Config,
) -> bool {
    use ra_tls::attestation::AttestationQuote;
    // Only TDX legacy verification downloads the image; skip it here and report
    // the os_image_hash as unverified rather than fetching an image.
    let needs_image_download = matches!(attestation.quote, AttestationQuote::DstackTdx(_))
        && attestation
            .decode_vm_config("")
            .map(|vm_config| vm_config.tdx_attestation_variant.is_legacy())
            .unwrap_or(true);
    if needs_image_download {
        return false;
    }
    let verifier = CvmVerifier::new(
        config.image_cache_dir.clone(),
        config.image_download_url.clone(),
        std::time::Duration::from_secs(config.image_download_timeout_secs),
        config.pccs_url.clone(),
    );
    let mut details = VerificationDetails::default();
    verifier
        .verify_os_image_hash(String::new(), attestation, false, &mut details)
        .await
        .is_ok()
}

#[rocket::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }

    let cli = Cli::parse();

    let default_config_str = include_str!("../dstack-verifier.toml");

    let figment = Figment::from(rocket::Config::default())
        .merge(Toml::string(default_config_str))
        .merge(Toml::file(&cli.config))
        .merge(Env::prefixed("DSTACK_VERIFIER_"));

    let config: Config = figment.extract().context("Failed to load configuration")?;

    // Check for oneshot modes
    if let Some(file_path) = cli.verify {
        if let Err(e) = run_oneshot(&file_path, &config).await {
            error!("Oneshot verification failed: {:#}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }
    if let Some(file_path) = cli.verify_cert {
        if let Err(e) = run_cert_oneshot(&file_path, &config).await {
            error!("certificate verification failed: {:#}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let verifier = Arc::new(CvmVerifier::new(
        config.image_cache_dir.clone(),
        config.image_download_url.clone(),
        std::time::Duration::from_secs(config.image_download_timeout_secs),
        config.pccs_url.clone(),
    ));

    rocket::custom(figment)
        .mount("/", rocket::routes![verify_cvm, health])
        .manage(verifier)
        .attach(AdHoc::on_liftoff("Startup", |_| {
            Box::pin(async {
                info!("dstack-verifier started successfully");
            })
        }))
        .launch()
        .await
        .map_err(|err| anyhow::anyhow!("launch rocket failed: {err:?}"))?;
    Ok(())
}
