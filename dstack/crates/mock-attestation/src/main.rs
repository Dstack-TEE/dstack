// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Generate development-only mock attestation assets")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate PKI roots and a manifest for every supported platform.
    Generate {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8088")]
        collateral_base_url: String,
    },
    /// Serve mock PCCS, AMD KDS and certificate collateral endpoints.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8088")]
        listen: std::net::SocketAddr,
        /// Write the roots matching this server instance into this directory.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Read the seed and collateral URL from a simulator config JSON file.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Run the deterministic SEV-SNP trust and mutation decision table.
    SevSnpMatrix,
    /// Run GCP vTPM and NitroTPM trust, binding, and substitution rows.
    CloudTpmMatrix,
    /// Run the Nitro Enclave document and image-policy decision table.
    NitroEnclaveMatrix,
}

#[derive(serde::Serialize)]
struct MatrixRow {
    name: &'static str,
    accepted: bool,
    stage: &'static str,
    diagnostic: String,
}

#[derive(serde::Serialize)]
struct CloudMatrixRow {
    platform: &'static str,
    name: &'static str,
    accepted: bool,
    stage: &'static str,
    diagnostic: String,
}

fn rejected(
    platform: &'static str,
    name: &'static str,
    stage: &'static str,
    error: anyhow::Error,
) -> CloudMatrixRow {
    CloudMatrixRow {
        platform,
        name,
        accepted: false,
        stage,
        diagnostic: format!("{error:#}"),
    }
}

fn expect_tpm_error(
    result: Result<tpm_qvl::verify::VerifiedReport, tpm_qvl::VerificationError>,
    message: &str,
) -> anyhow::Error {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error.into(),
    }
}

fn cloud_tpm_matrix() -> Result<Vec<CloudMatrixRow>> {
    use std::collections::BTreeMap;

    use mock_attestation::{nsm::NsmGenerator, tpm::TpmGenerator};

    let challenge = [0x42; 32];
    let report_data = [0x42; 64];
    let nonce = [0x24; 32];
    let public_key = [0x36; 65];
    let tpm = TpmGenerator::from_seed([0x71; 32], "http://127.0.0.1:8088")?;
    let tpm_verifier = tpm_qvl::QuoteVerifier::new(tpm.root_ca_pem());
    let quote = tpm.attest(&challenge)?;
    let verified_tpm = tpm_verifier
        .verify(&quote, &tpm.collateral())
        .context("valid GCP vTPM control failed")?;
    let mut rows = vec![CloudMatrixRow {
        platform: "gcp-tdx",
        name: "valid-vtpm",
        accepted: true,
        stage: "verified",
        diagnostic: String::new(),
    }];

    let wrong_tpm = TpmGenerator::from_seed([0x72; 32], "http://127.0.0.1:8088")?;
    rows.push(rejected(
        "gcp-tdx",
        "wrong-ak-root",
        "certificate-chain",
        expect_tpm_error(
            tpm_qvl::QuoteVerifier::new(wrong_tpm.root_ca_pem()).verify(&quote, &tpm.collateral()),
            "wrong TPM root accepted the quote",
        ),
    ));
    for (name, mutate, stage) in [
        ("quote-message", 0usize, "quote-signature"),
        ("quote-signature", 1usize, "quote-signature"),
    ] {
        let mut changed = quote.clone();
        if mutate == 0 {
            changed.message[10] ^= 1;
        } else {
            *changed
                .signature
                .last_mut()
                .context("empty TPM signature")? ^= 1;
        }
        rows.push(rejected(
            "gcp-tdx",
            name,
            stage,
            expect_tpm_error(
                tpm_verifier.verify(&changed, &tpm.collateral()),
                "modified TPM quote was accepted",
            ),
        ));
    }
    let mut changed_pcr = quote.clone();
    changed_pcr.pcr_values[0].value[0] ^= 1;
    rows.push(rejected(
        "gcp-tdx",
        "pcr-value",
        "pcr-replay",
        expect_tpm_error(
            tpm_verifier.verify(&changed_pcr, &tpm.collateral()),
            "TPM PCR substitution was accepted",
        ),
    ));
    rows.push(rejected(
        "gcp-tdx",
        "qualifying-data",
        "nonce-binding",
        mock_attestation::ensure_report_data(&verified_tpm.attest.qualified_data, &[0x25; 32])
            .expect_err("wrong TPM qualifying data was accepted"),
    ));

    let nsm = NsmGenerator::from_seed([0x73; 32])?;
    let pcrs = BTreeMap::from([
        (0u16, vec![0x10; 48]),
        (1u16, vec![0x11; 48]),
        (2u16, vec![0x12; 48]),
        (4u16, vec![0x14; 48]),
        (7u16, vec![0x17; 48]),
        (12u16, vec![0x1c; 48]),
        (14u16, vec![0x1e; 48]),
    ]);
    let document = nsm.attest_with_claims(
        Some(&report_data),
        Some(&nonce),
        Some(&public_key),
        pcrs.clone(),
    )?;
    let nsm_verifier = nsm_qvl::QuoteVerifier::new(nsm.root_ca_pem());
    let verified_nsm = nsm_verifier
        .verify(&document, None, None)
        .context("valid NitroTPM NSM control failed")?;
    rows.push(CloudMatrixRow {
        platform: "aws-nitro-tpm",
        name: "valid-nsm",
        accepted: true,
        stage: "verified",
        diagnostic: String::new(),
    });

    let wrong_nsm = NsmGenerator::from_seed([0x74; 32])?;
    rows.push(rejected(
        "aws-nitro-tpm",
        "wrong-nsm-root",
        "certificate-chain",
        nsm_qvl::QuoteVerifier::new(wrong_nsm.root_ca_pem())
            .verify(&document, None, None)
            .expect_err("wrong NSM root accepted the document"),
    ));
    let mut changed_document = document.clone();
    *changed_document.last_mut().context("empty NSM document")? ^= 1;
    rows.push(rejected(
        "aws-nitro-tpm",
        "cose-signature",
        "cose-signature",
        nsm_verifier
            .verify(&changed_document, None, None)
            .expect_err("modified NSM document was accepted"),
    ));
    for (name, actual, expected, stage) in [
        (
            "user-data",
            verified_nsm
                .user_data
                .clone()
                .context("missing user_data")?,
            vec![0x43; 64],
            "report-data",
        ),
        (
            "nonce",
            verified_nsm.nonce.clone().context("missing nonce")?,
            vec![0x25; 32],
            "nonce-binding",
        ),
        (
            "public-key",
            verified_nsm
                .public_key
                .clone()
                .context("missing public_key")?,
            vec![0x37; 65],
            "public-key-binding",
        ),
    ] {
        rows.push(rejected(
            "aws-nitro-tpm",
            name,
            stage,
            mock_attestation::ensure_report_data(&actual, &expected)
                .expect_err("wrong NSM binding value was accepted"),
        ));
    }
    let mut changed_pcrs = verified_nsm.pcrs.clone();
    changed_pcrs.get_mut(&14).context("missing PCR14")?[0] ^= 1;
    rows.push(rejected(
        "aws-nitro-tpm",
        "pcr14-event-replay",
        "event-log-replay",
        mock_attestation::ensure_report_data(&changed_pcrs[&14], &pcrs[&14])
            .expect_err("wrong NitroTPM PCR14 was accepted"),
    ));

    rows.push(rejected(
        "cross-cloud",
        "tpm-root-for-nsm",
        "platform-root-routing",
        nsm_qvl::QuoteVerifier::new(tpm.root_ca_pem())
            .verify(&document, None, None)
            .expect_err("TPM root accepted NSM evidence"),
    ));
    rows.push(rejected(
        "cross-cloud",
        "nsm-root-for-tpm",
        "platform-root-routing",
        expect_tpm_error(
            tpm_qvl::QuoteVerifier::new(nsm.root_ca_pem()).verify(&quote, &tpm.collateral()),
            "NSM root accepted TPM evidence",
        ),
    ));

    tpm_verifier
        .verify(&quote, &tpm.collateral())
        .context("GCP vTPM control did not recover")?;
    nsm_verifier
        .verify(&document, None, None)
        .context("NitroTPM NSM control did not recover")?;
    rows.push(CloudMatrixRow {
        platform: "cross-cloud",
        name: "valid-after-failures",
        accepted: true,
        stage: "recovery",
        diagnostic: String::new(),
    });
    Ok(rows)
}

fn nitro_enclave_matrix() -> Result<Vec<CloudMatrixRow>> {
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mock_attestation::nsm::{NsmDocumentOptions, NsmGenerator};
    use sha2::{Digest, Sha256};

    let generator = NsmGenerator::from_seed([0x81; 32])?;
    let verifier = nsm_qvl::QuoteVerifier::new(generator.root_ca_pem());
    let user_data = [0x42; 64];
    let nonce = [0x24; 32];
    let public_key = [0x36; 65];
    let pcrs = BTreeMap::from([
        (0u16, vec![0x10; 48]),
        (1u16, vec![0x11; 48]),
        (2u16, vec![0x12; 48]),
        (4u16, vec![0x14; 48]),
    ]);
    let document = generator.attest_with_claims(
        Some(&user_data),
        Some(&nonce),
        Some(&public_key),
        pcrs.clone(),
    )?;
    let verified = verifier
        .verify(&document, None, None)
        .context("valid Nitro Enclave control failed")?;
    let mut rows = vec![CloudMatrixRow {
        platform: "aws-nitro-enclave",
        name: "valid",
        accepted: true,
        stage: "verified",
        diagnostic: String::new(),
    }];

    let wrong = NsmGenerator::from_seed([0x82; 32])?;
    rows.push(rejected(
        "aws-nitro-enclave",
        "wrong-root",
        "certificate-chain",
        nsm_qvl::QuoteVerifier::new(wrong.root_ca_pem())
            .verify(&document, None, None)
            .expect_err("wrong NSM root accepted the document"),
    ));
    let mut changed_signature = document.clone();
    *changed_signature.last_mut().context("empty NSM document")? ^= 1;
    rows.push(rejected(
        "aws-nitro-enclave",
        "cose-signature",
        "cose-signature",
        verifier
            .verify(&changed_signature, None, None)
            .expect_err("modified COSE signature was accepted"),
    ));

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_millis() as u64;
    for (name, timestamp, needle) in [
        ("expired", now_ms.saturating_sub(3_600_000), "stale"),
        ("future", now_ms + 3_600_000, "future"),
    ] {
        let timed = generator.attest_with_options(
            Some(&user_data),
            Some(&nonce),
            Some(&public_key),
            pcrs.clone(),
            NsmDocumentOptions {
                timestamp_ms: Some(timestamp),
                ..Default::default()
            },
        )?;
        let error = verifier
            .verify(&timed, None, None)
            .expect_err("invalid document time was accepted");
        anyhow::ensure!(
            error.to_string().to_lowercase().contains(needle),
            "{name} did not reach freshness validation: {error:#}"
        );
        rows.push(rejected("aws-nitro-enclave", name, "freshness", error));
    }

    let missing_user_data =
        generator.attest_with_claims(None, Some(&nonce), Some(&public_key), pcrs.clone())?;
    let missing_verified = verifier.verify(&missing_user_data, None, None)?;
    rows.push(rejected(
        "aws-nitro-enclave",
        "missing-user-data",
        "report-data",
        anyhow::anyhow!(
            "NSM document does not contain user_data: {:?}",
            missing_verified.user_data
        ),
    ));
    for (name, actual, expected, stage) in [
        (
            "user-data",
            verified.user_data.clone().context("missing user_data")?,
            vec![0x43; 64],
            "report-data",
        ),
        (
            "nonce",
            verified.nonce.clone().context("missing nonce")?,
            vec![0x25; 32],
            "nonce-binding",
        ),
        (
            "public-key",
            verified.public_key.clone().context("missing public_key")?,
            vec![0x37; 65],
            "public-key-binding",
        ),
    ] {
        rows.push(rejected(
            "aws-nitro-enclave",
            name,
            stage,
            mock_attestation::ensure_report_data(&actual, &expected)
                .expect_err("wrong NSM binding was accepted"),
        ));
    }

    let other_module = generator.attest_with_options(
        Some(&user_data),
        Some(&nonce),
        Some(&public_key),
        pcrs.clone(),
        NsmDocumentOptions {
            module_id: "other-enclave".into(),
            ..Default::default()
        },
    )?;
    let other_module = verifier.verify(&other_module, None, None)?;
    rows.push(rejected(
        "aws-nitro-enclave",
        "module-id",
        "identity-binding",
        mock_attestation::ensure_report_data(
            other_module.module_id.as_bytes(),
            verified.module_id.as_bytes(),
        )
        .expect_err("cross-module identity was accepted"),
    ));

    for index in [0u16, 1, 2, 4] {
        let mut changed = pcrs.clone();
        changed.get_mut(&index).context("missing PCR")?[0] ^= 1;
        let signed = generator.attest_with_claims(
            Some(&user_data),
            Some(&nonce),
            Some(&public_key),
            changed,
        )?;
        let changed = verifier.verify(&signed, None, None)?;
        rows.push(rejected(
            "aws-nitro-enclave",
            match index {
                0 => "pcr0",
                1 => "pcr1",
                2 => "pcr2",
                _ => "pcr4",
            },
            "pcr-binding",
            mock_attestation::ensure_report_data(&changed.pcrs[&index], &pcrs[&index])
                .expect_err("changed signed PCR was accepted for the original identity"),
        ));
    }

    let image_hash = |values: &BTreeMap<u16, Vec<u8>>| {
        let mut hasher = Sha256::new();
        hasher.update(&values[&0]);
        hasher.update(&values[&1]);
        hasher.update(&values[&2]);
        hasher.finalize().to_vec()
    };
    rows.push(rejected(
        "aws-nitro-enclave",
        "os-image-hash",
        "image-binding",
        mock_attestation::ensure_report_data(&image_hash(&verified.pcrs), &[0x55; 32])
            .expect_err("wrong OS image hash was accepted"),
    ));

    let mut debug_pcrs = pcrs.clone();
    for index in 0..=2 {
        debug_pcrs.insert(index, vec![0; 48]);
    }
    let debug = generator.attest_with_claims(
        Some(&user_data),
        Some(&nonce),
        Some(&public_key),
        debug_pcrs,
    )?;
    let debug = verifier.verify(&debug, None, None)?;
    let is_debug = (0..=2).all(|index| debug.pcrs[&index].iter().all(|byte| *byte == 0));
    anyhow::ensure!(is_debug, "debug document did not preserve zero PCR0/1/2");
    rows.push(rejected(
        "aws-nitro-enclave",
        "debug-zero-pcrs",
        "debug-policy",
        anyhow::anyhow!("nitro enclave is in debug mode (PCR0/1/2 are zeroed)"),
    ));

    verifier
        .verify(&document, None, None)
        .context("valid Nitro Enclave control did not recover")?;
    rows.push(CloudMatrixRow {
        platform: "aws-nitro-enclave",
        name: "valid-after-failures",
        accepted: true,
        stage: "recovery",
        diagnostic: String::new(),
    });
    Ok(rows)
}

fn sev_snp_matrix() -> Result<Vec<MatrixRow>> {
    use mock_attestation::sev_snp::{SevSnpGenerator, SevSnpPolicy};

    let generator = SevSnpGenerator::from_seed([0x71; 32])?;
    let report_data = [0x42; 64];
    let valid = generator.attest(report_data)?;
    let verifier = sev_snp_qvl::QuoteVerifier::new(
        generator.root_ca_pem().into_bytes(),
        generator.root_ca_pem().into_bytes(),
        generator.root_ca_pem().into_bytes(),
    );
    let mut rows = Vec::new();

    verifier
        .verify(&valid.report, &valid.cert_chain, &report_data)
        .context("valid SEV-SNP control failed")?;
    rows.push(MatrixRow {
        name: "valid",
        accepted: true,
        stage: "verified",
        diagnostic: String::new(),
    });

    let wrong = SevSnpGenerator::from_seed([0x72; 32])?;
    let wrong_verifier = sev_snp_qvl::QuoteVerifier::new(
        wrong.root_ca_pem().into_bytes(),
        wrong.root_ca_pem().into_bytes(),
        wrong.root_ca_pem().into_bytes(),
    );
    let error = wrong_verifier
        .verify(&valid.report, &valid.cert_chain, &report_data)
        .expect_err("wrong root accepted SEV-SNP evidence");
    rows.push(MatrixRow {
        name: "wrong-root",
        accepted: false,
        stage: "certificate-chain",
        diagnostic: error.to_string(),
    });

    for (name, offset, stage) in [
        ("measurement", 0x90usize, "report-signature"),
        ("host-data", 0xc0, "report-signature"),
        ("reported-tcb", 0x180, "report-signature"),
        ("chip-id", 0x1a0, "report-signature"),
        ("signature", 0x2a0, "report-signature"),
    ] {
        let mut report = valid.report.clone();
        report[offset] ^= 1;
        let error = verifier
            .verify(&report, &valid.cert_chain, &report_data)
            .expect_err("unsigned field mutation was accepted");
        rows.push(MatrixRow {
            name,
            accepted: false,
            stage,
            diagnostic: error.to_string(),
        });
    }

    let error = verifier
        .verify(&valid.report, &valid.cert_chain, &[0x24; 64])
        .expect_err("wrong report data was accepted");
    rows.push(MatrixRow {
        name: "report-data-binding",
        accepted: false,
        stage: "report-data",
        diagnostic: error.to_string(),
    });

    for (name, policy, needle) in [
        (
            "debug-policy",
            SevSnpPolicy {
                debug_allowed: true,
                ..Default::default()
            },
            "debug",
        ),
        (
            "migration-policy",
            SevSnpPolicy {
                migration_agent_allowed: true,
                ..Default::default()
            },
            "migration",
        ),
    ] {
        let evidence = generator.attest_with_policy(report_data, [0x22; 32], [0x33; 48], policy)?;
        let error = verifier
            .verify(&evidence.report, &evidence.cert_chain, &report_data)
            .expect_err("unsafe signed guest policy was accepted");
        anyhow::ensure!(
            error.to_string().contains(needle),
            "{name} did not reach its policy check: {error:#}"
        );
        rows.push(MatrixRow {
            name,
            accepted: false,
            stage: "guest-policy",
            diagnostic: error.to_string(),
        });
    }

    verifier
        .verify(&valid.report, &valid.cert_chain, &report_data)
        .context("valid SEV-SNP control did not recover")?;
    rows.push(MatrixRow {
        name: "valid-after-failures",
        accepted: true,
        stage: "recovery",
        diagnostic: String::new(),
    });
    Ok(rows)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Generate {
            output,
            collateral_base_url,
        } => {
            mock_attestation::generate_assets_from_seed(
                &output,
                mock_attestation::random_seed(),
                &collateral_base_url,
            )?;
        }
        Command::Serve {
            listen,
            output,
            config,
        } => {
            let state = if let Some(path) = config {
                let config: dstack_types::TeeSimulatorConfig =
                    serde_json::from_slice(&fs_err::read(path)?)?;
                let seed = mock_attestation::parse_seed(
                    config
                        .mock_attestation_seed
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("mock_attestation_seed missing"))?,
                )?;
                let url = config
                    .collateral_base_url
                    .as_deref()
                    .unwrap_or("http://127.0.0.1:8088");
                std::sync::Arc::new(mock_attestation::server::MockCollateralState::from_seed(
                    seed, url,
                )?)
            } else {
                std::sync::Arc::new(mock_attestation::server::MockCollateralState::new()?)
            };
            if let Some(output) = output {
                state.write_roots(&output)?;
            }
            mock_attestation::server::serve(listen, state).await?;
        }
        Command::SevSnpMatrix => {
            println!("{}", serde_json::to_string_pretty(&sev_snp_matrix()?)?);
        }
        Command::CloudTpmMatrix => {
            println!("{}", serde_json::to_string_pretty(&cloud_tpm_matrix()?)?);
        }
        Command::NitroEnclaveMatrix => {
            println!(
                "{}",
                serde_json::to_string_pretty(&nitro_enclave_matrix()?)?
            );
        }
    }
    Ok(())
}
