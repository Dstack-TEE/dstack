// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use clap::Parser;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use rocket::{fairing::AdHoc, get, post, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

mod types;
mod verification;

use types::{VerificationRequest, VerificationResponse};
use verification::CvmVerifier;

#[derive(Parser)]
#[command(name = "dstack-verifier")]
#[command(about = "HTTP server providing CVM verification services")]
struct Cli {
    #[arg(short, long, default_value = "dstack-verifier.toml")]
    config: String,

    /// Oneshot mode: verify a single report JSON file and exit
    #[arg(long, value_name = "FILE")]
    verify: Option<String>,
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
    match verifier.verify(&request.into_inner()).await {
        Ok(response) => Json(response),
        Err(e) => {
            error!("Verification failed: {:?}", e);
            Json(VerificationResponse {
                is_valid: false,
                details: types::VerificationDetails {
                    quote_verified: false,
                    event_log_verified: false,
                    os_image_hash_verified: false,
                    report_data: None,
                    tcb_status: None,
                    advisory_ids: vec![],
                    app_info: None,
                    acpi_tables: None,
                    rtmr_debug: None,
                },
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
    let mut request: VerificationRequest = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse JSON: {}", e))?;

    // Ensure PCCS URL is populated from config when the report omits it
    request.pccs_url = request.pccs_url.or_else(|| config.pccs_url.clone());

    // Create verifier
    let verifier = CvmVerifier::new(
        config.image_cache_dir.clone(),
        config.image_download_url.clone(),
        std::time::Duration::from_secs(config.image_download_timeout_secs),
    );

    // Run verification
    info!("Starting verification...");
    let response = verifier.verify(&request).await?;

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
        println!("MRTD: {}", hex::encode(app_info.mrtd));
        println!("RTMR0: {}", hex::encode(app_info.rtmr0));
        println!("RTMR1: {}", hex::encode(app_info.rtmr1));
        println!("RTMR2: {}", hex::encode(app_info.rtmr2));
    }

    // Exit with appropriate code
    if !response.is_valid {
        std::process::exit(1);
    }

    Ok(())
}

#[rocket::launch]
fn rocket() -> _ {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let default_config_str = include_str!("../dstack-verifier.toml");

    let figment = Figment::from(rocket::Config::default())
        .merge(Toml::string(default_config_str))
        .merge(Toml::file(&cli.config))
        .merge(Env::prefixed("DSTACK_VERIFIER_"));

    let config: Config = figment.extract().expect("Failed to load configuration");

    // Check for oneshot mode
    if let Some(file_path) = cli.verify {
        // Run oneshot verification and exit
        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        rt.block_on(async {
            if let Err(e) = run_oneshot(&file_path, &config).await {
                error!("Oneshot verification failed: {:#}", e);
                std::process::exit(1);
            }
        });
        std::process::exit(0);
    }

    let verifier = Arc::new(CvmVerifier::new(
        config.image_cache_dir.clone(),
        config.image_download_url.clone(),
        std::time::Duration::from_secs(config.image_download_timeout_secs),
    ));

    rocket::custom(figment)
        .mount("/", rocket::routes![verify_cvm, health])
        .manage(verifier)
        .attach(AdHoc::on_liftoff("Startup", |_| {
            Box::pin(async {
                info!("dstack-verifier started successfully");
            })
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{ContentType, Status};
    use rocket::local::asynchronous::Client;

    #[tokio::test]
    async fn test_health_endpoint() {
        let client = Client::tracked(rocket())
            .await
            .expect("valid rocket instance");
        let response = client.get("/health").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn test_verify_endpoint_invalid_request() {
        let client = Client::tracked(rocket())
            .await
            .expect("valid rocket instance");
        let response = client
            .post("/verify")
            .header(ContentType::JSON)
            .body(r#"{"invalid": "request"}"#)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::UnprocessableEntity);
    }
}
