use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dstack_guest_agent_rpc::{dstack_guest_client::DstackGuestClient, RawQuoteArgs};
use dstack_kms_rpc::{kms_client::KmsClient, GetAppKeyRequest, SignCertRequest};
use http_client::prpc::PrpcClient;
use ra_rpc::client::{RaClient, RaClientConfig};
use ra_tls::{
    attestation::{QuoteContentType, VersionedAttestation},
    cert::{CaCert, CertConfigV2, CertRequest, CertSigningRequestV2, Csr},
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
use scale::Decode;
use serde_json::json;

#[derive(Parser)]
#[command(name = "kms-e2e-client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Probe TEE proxy to discover measurements for contract whitelisting
    Probe {
        /// Guest agent address (DSTACK_AGENT_ADDRESS)
        #[arg(long, env = "DSTACK_AGENT_ADDRESS")]
        agent_url: String,
    },
    /// Run authenticated KMS tests using TEE proxy attestation
    Test {
        /// KMS URL (https://...)
        #[arg(long)]
        kms_url: String,
        /// Guest agent address (DSTACK_AGENT_ADDRESS)
        #[arg(long, env = "DSTACK_AGENT_ADDRESS")]
        agent_url: String,
        /// VM config JSON string to pass to GetAppKey
        #[arg(long, default_value = "{}")]
        vm_config: String,
    },
}

fn dstack_client(agent_url: &str) -> DstackGuestClient<PrpcClient> {
    let http_client = PrpcClient::new(agent_url.to_string());
    DstackGuestClient::new(http_client)
}

async fn gen_ra_cert(
    agent_url: &str,
    ca_cert_pem: String,
    ca_key_pem: String,
) -> Result<(String, String)> {
    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let response = dstack_client(agent_url)
        .attest(RawQuoteArgs {
            report_data: report_data.to_vec(),
        })
        .await
        .context("Failed to get quote from TEE proxy")?;
    let attestation = VersionedAttestation::decode(&mut &response.attestation[..])
        .context("Invalid attestation")?;
    let req = CertRequest::builder()
        .subject("RA-TLS E2E Test Cert")
        .attestation(&attestation)
        .key(&key)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}

async fn cmd_probe(agent_url: &str) -> Result<()> {
    let client = dstack_client(agent_url);

    // Get app info from the TEE proxy
    let info = client.info().await.context("Failed to get info from TEE proxy")?;

    let result = json!({
        "app_id": format!("0x{}", hex::encode(&info.app_id)),
        "instance_id": format!("0x{}", hex::encode(&info.instance_id)),
        "device_id": format!("0x{}", hex::encode(&info.device_id)),
        "mr_aggregated": format!("0x{}", hex::encode(&info.mr_aggregated)),
        "os_image_hash": format!("0x{}", hex::encode(&info.os_image_hash)),
        "compose_hash": format!("0x{}", hex::encode(&info.compose_hash)),
        "vm_config": info.vm_config,
    });

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn cmd_test(kms_url: &str, agent_url: &str, vm_config: &str) -> Result<()> {
    // RaClient expects the URL to include /prpc suffix
    let kms_prpc_url = format!("{}/prpc", kms_url.trim_end_matches('/'));

    // Step 1: Get temp CA cert from KMS (unauthenticated)
    eprintln!("Getting temp CA cert from KMS...");
    let kms_client_noauth = RaClient::new(kms_prpc_url.clone(), true)?;
    let kms_noauth = KmsClient::new(kms_client_noauth);
    let tmp_ca = kms_noauth
        .get_temp_ca_cert()
        .await
        .context("Failed to get temp CA cert")?;
    eprintln!("Got temp CA cert");

    // Step 2: Get KMS root CA for TLS verification
    let meta = kms_noauth
        .get_meta()
        .await
        .context("Failed to get KMS metadata")?;
    let root_ca_cert = meta.ca_cert.clone();
    eprintln!("Got KMS root CA");

    // Step 3: Generate RA-TLS cert using TEE proxy
    eprintln!("Generating RA-TLS cert via TEE proxy...");
    let (ra_cert, ra_key) = gen_ra_cert(agent_url, tmp_ca.temp_ca_cert, tmp_ca.temp_ca_key)
        .await
        .context("Failed to generate RA cert")?;
    eprintln!("RA-TLS cert generated");

    // Step 4: Create authenticated mTLS client
    let ra_client = RaClientConfig::builder()
        .remote_uri(kms_prpc_url.clone())
        .tls_client_cert(ra_cert)
        .tls_client_key(ra_key)
        .tls_ca_cert(root_ca_cert)
        .tls_built_in_root_certs(false)
        .tls_no_check_hostname(true)
        .verify_server_attestation(false)
        .build()
        .into_client()
        .context("Failed to create RA client")?;
    let kms_auth = KmsClient::new(ra_client);

    // Test: GetAppKey
    eprintln!("Testing GetAppKey...");
    let result = kms_auth
        .get_app_key(GetAppKeyRequest {
            api_version: 1,
            vm_config: vm_config.to_string(),
        })
        .await;
    match &result {
        Ok(resp) => {
            let output = json!({
                "test": "GetAppKey",
                "status": "ok",
                "has_disk_crypt_key": !resp.disk_crypt_key.is_empty(),
                "has_env_crypt_key": !resp.env_crypt_key.is_empty(),
                "has_k256_key": !resp.k256_key.is_empty(),
                "gateway_app_id": resp.gateway_app_id,
            });
            println!("{}", serde_json::to_string(&output)?);
        }
        Err(e) => {
            let output = json!({
                "test": "GetAppKey",
                "status": "error",
                "error": format!("{e:#}"),
            });
            println!("{}", serde_json::to_string(&output)?);
        }
    }

    // Test: SignCert
    eprintln!("Testing SignCert...");
    let sign_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = sign_key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let attest_response = dstack_client(agent_url)
        .attest(RawQuoteArgs {
            report_data: report_data.to_vec(),
        })
        .await
        .context("Failed to get quote for SignCert")?;
    let attestation = VersionedAttestation::decode(&mut &attest_response.attestation[..])
        .context("Invalid attestation for SignCert")?;
    let csr = CertSigningRequestV2 {
        confirm: "please sign cert:".to_string(),
        pubkey,
        config: CertConfigV2 {
            org_name: None,
            subject: "e2e-test.dstack".to_string(),
            subject_alt_names: vec![],
            usage_server_auth: true,
            usage_client_auth: false,
            ext_quote: true,
            ext_app_info: false,
            not_before: None,
            not_after: None,
        },
        attestation,
    };
    let signature = csr.signed_by(&sign_key).context("Failed to sign CSR")?;
    let result = kms_auth
        .sign_cert(SignCertRequest {
            api_version: 2,
            csr: csr.to_vec(),
            signature,
            vm_config: vm_config.to_string(),
        })
        .await;
    match &result {
        Ok(resp) => {
            let output = json!({
                "test": "SignCert",
                "status": "ok",
                "cert_chain_len": resp.certificate_chain.len(),
            });
            println!("{}", serde_json::to_string(&output)?);
        }
        Err(e) => {
            let output = json!({
                "test": "SignCert",
                "status": "error",
                "error": format!("{e:#}"),
            });
            println!("{}", serde_json::to_string(&output)?);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match &cli.command {
        Commands::Probe { agent_url } => cmd_probe(agent_url).await,
        Commands::Test {
            kms_url,
            agent_url,
            vm_config,
        } => cmd_test(kms_url, agent_url, vm_config).await,
    }
}
