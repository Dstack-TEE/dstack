// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

mod simulator;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use dstack_guest_agent::{
    backend::PlatformBackend,
    config::{self, Config},
    AppState, run_server,
};
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use ra_rpc::Attestation;
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
}

#[derive(Debug, Clone, Deserialize)]
struct SimulatorCoreConfig {
    #[serde(flatten)]
    core: Config,
    simulator: SimulatorSettings,
}

struct SimulatorPlatform {
    attestation: VersionedAttestation,
}

impl SimulatorPlatform {
    fn new(attestation: VersionedAttestation) -> Self {
        Self { attestation }
    }
}

impl PlatformBackend for SimulatorPlatform {
    fn attestation_for_info(&self) -> Result<Attestation> {
        Ok(simulator::simulated_info_attestation(&self.attestation))
    }

    fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation> {
        Ok(simulator::simulated_certificate_attestation(&self.attestation, pubkey))
    }

    fn quote_response(&self, report_data: [u8; 64], vm_config: &str) -> Result<GetQuoteResponse> {
        simulator::simulated_quote_response(&self.attestation, report_data, vm_config)
    }

    fn attest_response(&self, _report_data: [u8; 64]) -> Result<AttestResponse> {
        Ok(simulator::simulated_attest_response(&self.attestation))
    }

    fn emit_event(&self, event: &str, _payload: &[u8]) -> Result<()> {
        bail!("runtime event emission is unavailable in simulator mode: {event}")
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
    warn!(attestation_file = %sim_config.simulator.attestation_file, "starting dstack guest-agent simulator");
    let attestation = simulator::load_versioned_attestation(&sim_config.simulator.attestation_file)?;
    let state = AppState::new(sim_config.core, Arc::new(SimulatorPlatform::new(attestation)))
        .await
        .context("Failed to create simulator app state")?;
    run_server(state, figment, args.watchdog).await
}


#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixture_platform() -> SimulatorPlatform {
        let fixture = simulator::load_versioned_attestation(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest-agent/fixtures/attestation.bin"),
        )
        .expect("fixture attestation should load");
        SimulatorPlatform::new(fixture)
    }

    #[test]
    fn simulator_rejects_runtime_event_emission() {
        let platform = load_fixture_platform();
        let err = platform.emit_event("test.event", b"payload").unwrap_err();
        assert!(err.to_string().contains("unavailable in simulator mode"));
    }

    #[test]
    fn simulator_provides_certificate_attestation() {
        let platform = load_fixture_platform();
        let cert_attestation = platform.certificate_attestation(b"test-public-key").unwrap();
        assert!(cert_attestation.decode_app_info(false).is_ok());
        let _ = platform.attestation_for_info().unwrap();
    }
}
