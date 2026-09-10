// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{net::IpAddr, path::Path, sync::Arc};

use anyhow::{Context, Result};
use clap::Parser;
use dstack_attest::attestation::AttestationVerifierConfig;
use dstack_verifier::{
    CvmVerifier, VerificationDetails, VerificationRequest, VerificationResponse,
};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use ra_tls::attestation::AttestationVerifier;
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
#[serde(deny_unknown_fields)]
pub struct Config {
    pub address: String,
    pub port: u16,
    pub image_cache_dir: String,
    #[serde(default)]
    pub attestation: AttestationVerifierConfig,
    pub image_download_url: String,
    pub image_download_timeout_secs: u64,
}

impl Config {
    fn validate(&self) -> Result<()> {
        self.address
            .parse::<IpAddr>()
            .with_context(|| format!("invalid verifier address: {}", self.address))?;
        anyhow::ensure!(self.port != 0, "verifier port must not be zero");
        anyhow::ensure!(
            !self.image_cache_dir.trim().is_empty(),
            "image_cache_dir must not be empty"
        );
        anyhow::ensure!(
            self.image_download_timeout_secs > 0,
            "image_download_timeout_secs must be greater than zero"
        );
        anyhow::ensure!(
            self.image_download_url.contains("{OS_IMAGE_HASH}"),
            "image_download_url must contain {{OS_IMAGE_HASH}}"
        );
        anyhow::ensure!(
            self.image_download_url.starts_with("http://")
                || self.image_download_url.starts_with("https://"),
            "image_download_url must use http or https"
        );
        let probe_url = self
            .image_download_url
            .replace("{OS_IMAGE_HASH}", &"00".repeat(32));
        let parsed = reqwest::Url::parse(&probe_url).context("invalid image_download_url")?;
        debug_assert!(matches!(parsed.scheme(), "http" | "https"));
        Ok(())
    }
}

fn config_figment(config_path: &Path) -> Figment {
    Figment::new()
        .merge(Toml::string(include_str!("../dstack-verifier.toml")))
        .merge(Toml::file(config_path))
        .merge(Env::prefixed("DSTACK_VERIFIER_").split("__"))
}

fn load_config(figment: &Figment) -> Result<Config> {
    let config: Config = figment.extract().context("Failed to load configuration")?;
    config.validate()?;
    Ok(config)
}

fn socket_addr(config: &Config) -> Result<std::net::SocketAddr> {
    let ip = config
        .address
        .parse::<IpAddr>()
        .with_context(|| format!("invalid verifier address: {}", config.address))?;
    Ok(std::net::SocketAddr::from((ip, config.port)))
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

async fn run_oneshot(file_path: &str, config: &Config) -> anyhow::Result<bool> {
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
        Arc::new(AttestationVerifier::load(&config.attestation)?),
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

    // Emit exactly one machine-readable document on stdout.
    println!("{}", serde_json::to_string(&response)?);
    Ok(response.is_valid)
}

fn verify_certificate_profile(cert_der: &[u8]) -> anyhow::Result<()> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .context("failed to parse X.509 certificate")?;
    cert.verify_signature(None)
        .context("certificate self-signature verification failed")?;
    if !cert.validity().is_valid() {
        anyhow::bail!("certificate is outside its validity period");
    }
    let key_usage = cert
        .key_usage()
        .context("failed to decode certificate key usage")?
        .context("certificate key usage extension missing")?;
    if !key_usage.value.digital_signature() {
        anyhow::bail!("certificate key usage does not permit digital signatures");
    }
    let extended = cert
        .extended_key_usage()
        .context("failed to decode certificate extended key usage")?
        .context("certificate extended key usage extension missing")?;
    if !extended.value.server_auth && !extended.value.client_auth {
        anyhow::bail!(
            "certificate extended key usage permits neither server nor client authentication"
        );
    }
    let san = cert
        .subject_alternative_name()
        .context("failed to decode certificate SAN")?
        .context("certificate SAN extension missing")?;
    if san.value.general_names.is_empty() {
        anyhow::bail!("certificate SAN extension is empty");
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

    let cert_der = if cert.starts_with(b"-----BEGIN") {
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(&cert).context("failed to parse PEM certificate")?;
        pem.contents
    } else {
        cert
    };
    verify_certificate_profile(&cert_der)?;

    let attestation_verifier = Arc::new(AttestationVerifier::load(&config.attestation)?);
    let verified = ra_tls::attestation::verify_der(&cert_der, attestation_verifier.as_ref())
        .await
        .map_err(|e| anyhow::anyhow!("failed to verify RA-TLS certificate: {:#}", e))?;

    let app_info = verified.decode_app_info(false).ok();
    // Bind the reported os_image_hash to the attested boot measurement. For
    // every platform except TDX legacy this is a self-contained check (no image
    // download); relying parties should only trust `os_image_hash` when
    // `os_image_hash_verified` is true.
    let os_image_hash_verified =
        verify_cert_os_image_hash(&verified.attestation, config, &attestation_verifier).await;
    let output = serde_json::json!({
        "is_valid": true,
        "details": {
            "tee_variant": verified.attestation.quote.variant(),
            "report_data": hex::encode(verified.attestation.report_data),
            "public_key_der": hex::encode(&verified.public_key_der),
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
    attestation_verifier: &Arc<AttestationVerifier>,
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
        attestation_verifier.clone(),
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
        fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .init();
    }

    let cli = Cli::parse();

    let config_path = Path::new(&cli.config);
    let config_figment = config_figment(config_path);
    let config = load_config(&config_figment)?;
    // Check for oneshot modes
    if let Some(file_path) = cli.verify {
        let (response, exit_code) = match run_oneshot(&file_path, &config).await {
            Ok(is_valid) => (None, if is_valid { 0 } else { 1 }),
            Err(error) => {
                error!("Oneshot verification failed: {error:#}");
                (
                    Some(VerificationResponse {
                        is_valid: false,
                        details: VerificationDetails::default(),
                        reason: Some(format!("Internal error: {error:#}")),
                    }),
                    1,
                )
            }
        };
        if let Some(response) = response {
            println!("{}", serde_json::to_string(&response)?);
        }
        std::process::exit(exit_code);
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
        Arc::new(AttestationVerifier::load(&config.attestation)?),
    ));

    let addr = socket_addr(&config)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    let rocket_figment = Figment::from(rocket::Config::default()).merge(config_figment);
    rocket::custom(rocket_figment)
        .mount("/", rocket::routes![verify_cvm, health])
        .manage(verifier)
        .attach(AdHoc::on_liftoff("Startup", |_| {
            Box::pin(async {
                info!("dstack-verifier started successfully");
            })
        }))
        .launch_on(listener)
        .await
        .map_err(|err| anyhow::anyhow!("launch rocket failed: {err:?}"))?;
    Ok(())
}

#[cfg(test)]
mod config_tests {
    use super::*;

    fn valid_config(extra: &str) -> String {
        format!(
            r#"address = "127.0.0.1"
port = 18080
image_cache_dir = "/tmp/dstack-verifier-config-test"
image_download_url = "http://127.0.0.1:18081/{{OS_IMAGE_HASH}}.tar.gz"
image_download_timeout_secs = 7
{extra}
"#
        )
    }

    #[test]
    fn config_file_precedence_validation_and_unknown_field_matrix() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("verifier.toml");
        std::fs::write(&path, valid_config("")).unwrap();
        let loaded = load_config(&config_figment(&path)).unwrap();
        assert_eq!(loaded.address, "127.0.0.1");
        assert_eq!(loaded.port, 18080);
        assert_eq!(loaded.image_download_timeout_secs, 7);
        assert_eq!(
            socket_addr(&loaded).unwrap(),
            "127.0.0.1:18080".parse().unwrap()
        );

        for (name, body, expected) in [
            (
                "zero-port",
                valid_config("").replace("port = 18080", "port = 0"),
                "port must not be zero",
            ),
            (
                "empty-cache",
                valid_config("").replace("/tmp/dstack-verifier-config-test", ""),
                "image_cache_dir must not be empty",
            ),
            (
                "zero-timeout",
                valid_config("").replace("timeout_secs = 7", "timeout_secs = 0"),
                "must be greater than zero",
            ),
            (
                "missing-placeholder",
                valid_config("").replace("/{OS_IMAGE_HASH}.tar.gz", "/image.tar.gz"),
                "must contain {OS_IMAGE_HASH}",
            ),
            (
                "invalid-scheme",
                valid_config("").replace("http://", "file://"),
                "must use http or https",
            ),
            (
                "unknown-field",
                valid_config("unknown_policy = true"),
                "unknown field",
            ),
        ] {
            std::fs::write(&path, body).unwrap();
            let error = load_config(&config_figment(&path)).expect_err(name);
            assert!(format!("{error:#}").contains(expected), "{name}: {error:#}");
        }

        std::fs::write(&path, valid_config("")).unwrap();
        assert_eq!(load_config(&config_figment(&path)).unwrap().port, 18080);
    }
}

#[cfg(test)]
mod certificate_profile_tests {
    use super::*;
    use ra_tls::cert::CertRequest;
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
    use std::time::{Duration, SystemTime};

    fn certificate(not_before: SystemTime, not_after: SystemTime) -> Vec<u8> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let alt_names = vec!["clock-boundary.example.test".to_string()];
        CertRequest::builder()
            .key(&key)
            .subject("clock-boundary.example.test")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .not_before(not_before)
            .not_after(not_after)
            .build()
            .self_signed()
            .unwrap()
            .der()
            .to_vec()
    }

    #[test]
    fn certificate_profile_rejects_expired_and_future_certificates() {
        let now = SystemTime::now();
        let hour = Duration::from_secs(60 * 60);

        let expired = certificate(now - hour * 2, now - hour);
        let future = certificate(now + hour, now + hour * 2);
        let current = certificate(now - hour, now + hour);

        for invalid in [&expired, &future] {
            let error = verify_certificate_profile(invalid).unwrap_err();
            assert!(
                format!("{error:#}").contains("outside its validity period"),
                "unexpected validity diagnostic: {error:#}"
            );
        }
        verify_certificate_profile(&current).unwrap();
    }
}
