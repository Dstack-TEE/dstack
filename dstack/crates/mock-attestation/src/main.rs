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
}

#[derive(serde::Serialize)]
struct MatrixRow {
    name: &'static str,
    accepted: bool,
    stage: &'static str,
    diagnostic: String,
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
    }
    Ok(())
}
