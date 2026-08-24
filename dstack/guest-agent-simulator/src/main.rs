// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

mod simulator;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use dstack_guest_agent::{
    backend::PlatformBackend,
    config::{self, Config},
    run_server, AppState,
};
use dstack_guest_agent_rpc::GetQuoteResponse;
use mock_attestation::tdx::TdxGenerator;
use ra_tls::attestation::VersionedAttestation;
use serde::Deserialize;
use tracing::warn;

const DEFAULT_CONFIG: &str = include_str!("../dstack.toml");

#[derive(Parser)]
#[command(author, version, about = "dstack guest agent simulator", long_version = dstack_guest_agent::app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Enable systemd watchdog
    #[arg(short, long)]
    watchdog: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct SimulatorSettings {
    attestation_file: String,
    #[serde(default = "default_patch_report_data")]
    patch_report_data: bool,
    #[serde(default)]
    mock_attestation_seed: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SimulatorCoreConfig {
    #[serde(flatten)]
    core: Config,
    simulator: SimulatorSettings,
}

struct SimulatorPlatform {
    attestation: VersionedAttestation,
    patch_report_data: bool,
    generator: Option<TdxGenerator>,
}

impl SimulatorPlatform {
    fn new(
        attestation: VersionedAttestation,
        patch_report_data: bool,
        mock_attestation_seed: Option<&str>,
    ) -> Result<Self> {
        let generator = mock_attestation_seed
            .map(mock_attestation::parse_seed)
            .transpose()?
            .map(TdxGenerator::from_seed)
            .transpose()?;
        Ok(Self {
            attestation,
            patch_report_data,
            generator,
        })
    }
}

fn default_patch_report_data() -> bool {
    true
}

impl PlatformBackend for SimulatorPlatform {
    fn attestation_for_info(&self) -> Result<VersionedAttestation> {
        Ok(simulator::simulated_info_attestation(&self.attestation))
    }

    fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation> {
        simulator::simulated_certificate_attestation(
            &self.attestation,
            pubkey,
            self.patch_report_data,
            self.generator.as_ref(),
        )
    }

    fn quote_response(&self, report_data: [u8; 64], vm_config: &str) -> Result<GetQuoteResponse> {
        simulator::simulated_quote_response(
            &self.attestation,
            report_data,
            vm_config,
            self.patch_report_data,
            self.generator.as_ref(),
        )
    }

    fn attestation_for_report_data(&self, report_data: [u8; 64]) -> Result<VersionedAttestation> {
        simulator::simulated_attest_response(
            &self.attestation,
            report_data,
            self.patch_report_data,
            self.generator.as_ref(),
        )
    }
}

#[rocket::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }
    let args = Args::parse();
    let figment = config::load_config_figment_with_default(DEFAULT_CONFIG, args.config.as_deref());
    let sim_config: SimulatorCoreConfig = figment
        .focus("core")
        .extract()
        .context("Failed to extract simulator core config")?;
    warn!(
        attestation_file = %sim_config.simulator.attestation_file,
        patch_report_data = sim_config.simulator.patch_report_data,
        signed_quotes = sim_config.simulator.mock_attestation_seed.is_some(),
        "starting dstack guest-agent simulator"
    );
    if sim_config.simulator.patch_report_data {
        warn!(
            "simulator will rewrite report_data to match requests; quote verification may fail against the original fixture signature"
        );
    } else {
        warn!(
            "simulator will preserve fixture report_data; cert/key binding and requested report_data may not match"
        );
    }
    let attestation =
        simulator::load_versioned_attestation(&sim_config.simulator.attestation_file)?;
    let state = AppState::new_with_platform(
        sim_config.core,
        Arc::new(SimulatorPlatform::new(
            attestation,
            sim_config.simulator.patch_report_data,
            sim_config.simulator.mock_attestation_seed.as_deref(),
        )?),
    )
    .await
    .context("Failed to create simulator app state")?;
    run_server(state, figment, args.watchdog).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ra_tls::attestation::TdxAttestationExt;

    fn load_fixture_platform() -> SimulatorPlatform {
        let fixture = simulator::load_versioned_attestation(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../guest-agent/fixtures/attestation.bin"),
        )
        .expect("fixture attestation should load");
        SimulatorPlatform::new(fixture, true, None).unwrap()
    }

    #[test]
    fn simulator_provides_certificate_attestation() {
        let platform = load_fixture_platform();
        let cert_attestation = platform
            .certificate_attestation(b"test-public-key")
            .unwrap();
        assert!(cert_attestation.into_v1().decode_app_info(false).is_ok());
        let _ = platform.attestation_for_info().unwrap();
    }

    #[test]
    fn simulator_attest_response_preserves_legacy_wire_format() {
        let platform = load_fixture_platform();
        let report_data = [0x5a; 64];
        let encoded = platform
            .attestation_for_report_data(report_data)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(encoded.first(), Some(&0x00));
        let patched = VersionedAttestation::from_bytes(&encoded)
            .unwrap()
            .into_v1();
        assert_eq!(patched.report_data().unwrap(), report_data);
    }

    #[test]
    fn seeded_simulator_resigns_certificate_attestation() {
        let fixture = simulator::load_versioned_attestation(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../guest-agent/fixtures/attestation.bin"),
        )
        .unwrap();
        let seed = [0x5a; 32];
        let platform = SimulatorPlatform::new(fixture, true, Some(&hex::encode(seed))).unwrap();
        let attestation = platform
            .certificate_attestation(b"test-public-key")
            .unwrap()
            .into_v1();
        let quote = attestation.tdx_quote_bytes().unwrap();
        let generator = TdxGenerator::from_seed(seed).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        dcap_qvl::verify::QuoteVerifier::new(generator.root_ca_der())
            .verify(&quote, &generator.sample_collateral().unwrap(), now)
            .unwrap();
        assert_eq!(
            attestation.report_data().unwrap(),
            ra_tls::attestation::QuoteContentType::RaTlsCert.to_report_data(b"test-public-key")
        );
    }

    #[test]
    fn simulator_rejects_get_quote_on_non_tdx() {
        use ra_tls::attestation::PlatformEvidence;

        let fixture = simulator::load_versioned_attestation(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../guest-agent/fixtures/attestation.bin"),
        )
        .expect("fixture attestation should load");
        let mut attestation = fixture.into_v1();
        attestation.platform = PlatformEvidence::SevSnp {
            report: vec![0u8; 1184],
            cert_chain: Vec::new(),
            mr_config: String::new(),
        };
        let non_tdx = VersionedAttestation::V1 { attestation };
        let report_data = [0x5a; 64];

        // GetQuote is Intel TDX only.
        let err = simulator::simulated_quote_response(&non_tdx, report_data, "", true, None)
            .expect_err("GetQuote must fail on a non-TDX platform");
        assert!(
            err.to_string().contains("Intel TDX only"),
            "unexpected error: {err}"
        );

        // Attest remains the supported path on the same platform.
        simulator::simulated_attest_response(&non_tdx, report_data, true, None)
            .expect("Attest must still work on a non-TDX platform");
    }

    #[test]
    fn simulator_serves_get_quote_on_gcp_tdx() {
        use dstack_types::Platform;
        use ra_tls::attestation::{PlatformEvidence, TpmQuote};

        let fixture = simulator::load_versioned_attestation(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../guest-agent/fixtures/attestation.bin"),
        )
        .expect("fixture attestation should load");
        let mut attestation = fixture.into_v1();
        let (quote, event_log) = match attestation.platform {
            PlatformEvidence::Tdx { quote, event_log } => (quote, event_log),
            other => panic!("fixture should carry bare TDX evidence, got {other:?}"),
        };
        attestation.platform = PlatformEvidence::GcpTdx {
            quote,
            event_log,
            tpm_quote: TpmQuote {
                message: Vec::new(),
                signature: Vec::new(),
                pcr_values: Vec::new(),
                ak_cert: Vec::new(),
                platform: Platform::Gcp,
                event_log: Vec::new(),
            },
        };
        let gcp_tdx = VersionedAttestation::V1 { attestation };
        let report_data = [0x5a; 64];

        // The gate is "does this platform have a TDX quote", not "is this bare
        // TDX", so GCP Confidential VMs are served, with the report data
        // patched into the quote the same way bare TDX gets it.
        let response = simulator::simulated_quote_response(&gcp_tdx, report_data, "", true, None)
            .expect("GetQuote must answer on GCP TDX");
        assert_eq!(
            &response.quote[ra_tls::attestation::TDX_QUOTE_REPORT_DATA_RANGE],
            &report_data
        );
        assert_eq!(response.report_data, report_data);

        // What the response cannot carry is the vTPM quote GCP's verification
        // also binds -- it has no field for one. That is why the docs point
        // relying parties on GCP at Attest.
        let attested = simulator::simulated_attest_response(&gcp_tdx, report_data, true, None)
            .expect("Attest must work on GCP TDX too");
        let round_tripped = VersionedAttestation::from_bytes(&attested.to_bytes().unwrap())
            .unwrap()
            .into_v1();
        assert!(round_tripped.platform.tpm_quote().is_some());
    }

    #[test]
    fn simulator_can_preserve_fixture_report_data() {
        let fixture = simulator::load_versioned_attestation(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../guest-agent/fixtures/attestation.bin"),
        )
        .expect("fixture attestation should load");
        let original = fixture.clone().into_v1().report_data().unwrap();
        let platform = SimulatorPlatform::new(fixture, false, None).unwrap();
        let report_data = [0x5a; 64];
        let encoded = platform
            .attestation_for_report_data(report_data)
            .unwrap()
            .to_bytes()
            .unwrap();
        let patched = VersionedAttestation::from_bytes(&encoded)
            .unwrap()
            .into_v1();
        assert_eq!(patched.report_data().unwrap(), original);
        assert_ne!(patched.report_data().unwrap(), report_data);
    }
}
