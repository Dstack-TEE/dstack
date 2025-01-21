use clap::Parser;
use fs_err as fs;
use ra_tls::{
    cert::{CaCert, CertRequest},
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Generate certificates for the KMS system
    Generate {
        /// Domain name for the generated certificates
        #[arg(short, long)]
        domain: String,

        /// Output directory for the generated certificates
        #[arg(short, long, default_value = "certs")]
        output_dir: String,
    },
    /// Sign a certificate using an existing CA
    Sign {
        /// Domain name for the generated certificate
        #[arg(short, long)]
        domain: String,

        /// CA key file
        #[arg(long)]
        ca_key: String,

        /// CA cert file
        #[arg(long)]
        ca_cert: String,

        /// Output cert file
        #[arg(long)]
        cert: String,

        /// Output key file
        #[arg(long)]
        key: String,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Generate { domain, output_dir } => {
            generate_and_store_certificates(&domain, &output_dir)?;
        }
        Commands::Sign {
            domain,
            ca_key,
            ca_cert,
            cert,
            key,
        } => {
            sign_certificate(&domain, &ca_key, &ca_cert, &cert, &key)?;
        }
    }
    Ok(())
}

fn generate_and_store_certificates(domain: &str, output_dir: &str) -> anyhow::Result<()> {
    let tmp_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let kms_rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let tproxy_rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let tmp_ca_cert = CertRequest::builder()
        .org_name("Phala Network")
        .subject("Phala KMS Client Temp CA")
        .ca_level(1)
        .key(&tmp_ca_key)
        .build()
        .self_signed()?;

    // Create self-signed KMS cert
    let ca_cert = CertRequest::builder()
        .org_name("Phala Network")
        .subject("Phala KMS CA")
        .ca_level(3)
        .key(&ca_key)
        .build()
        .self_signed()?;

    let kms_domain = format!("kms.{domain}");
    // Sign WWW server cert with KMS cert
    let kms_rpc_cert = CertRequest::builder()
        .subject(&kms_domain)
        .alt_names(&[kms_domain.clone()])
        .key(&kms_rpc_key)
        .build()
        .signed_by(&ca_cert, &ca_key)?;

    let tproxy_domain = format!("tproxy.{domain}");
    let tproxy_rpc_cert = CertRequest::builder()
        .subject(&tproxy_domain)
        .alt_names(&[tproxy_domain.clone()])
        .key(&tproxy_rpc_key)
        .build()
        .signed_by(&ca_cert, &ca_key)?;

    store_cert(
        output_dir,
        "tmp-ca",
        &tmp_ca_cert.pem(),
        &tmp_ca_key.serialize_pem(),
    )?;
    store_cert(
        output_dir,
        "root-ca",
        &ca_cert.pem(),
        &ca_key.serialize_pem(),
    )?;
    store_cert(
        output_dir,
        "kms-rpc",
        &kms_rpc_cert.pem(),
        &kms_rpc_key.serialize_pem(),
    )?;
    store_cert(
        output_dir,
        "tproxy-rpc",
        &tproxy_rpc_cert.pem(),
        &tproxy_rpc_key.serialize_pem(),
    )?;

    Ok(())
}

fn store_cert(path: &str, name: &str, cert: &str, key: &str) -> anyhow::Result<()> {
    let cert_path = format!("{}/{}.cert", path, name);
    let key_path = format!("{}/{}.key", path, name);
    fs::write(cert_path, cert)?;
    fs::write(key_path, key)?;
    Ok(())
}

fn sign_certificate(
    domain: &str,
    ca_key_path: &str,
    ca_cert_path: &str,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<()> {
    let ca_key = fs::read_to_string(ca_key_path)?;
    let ca_cert = fs::read_to_string(ca_cert_path)?;
    let ca = CaCert::new(ca_cert.clone(), ca_key)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let alt_names = [domain.to_string()];
    let req = CertRequest::builder()
        .subject(domain)
        .alt_names(&alt_names)
        .key(&key)
        .build();
    let cert = ca.sign(req)?;

    let cert_chain = format!("{}\n{}", cert.pem(), ca_cert);
    fs::write(cert_path, cert_chain)?;
    fs::write(key_path, key.serialize_pem())?;
    Ok(())
}
