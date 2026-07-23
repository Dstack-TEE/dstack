// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Development-only attestation PKI and evidence generation.
//!
//! Private keys produced by this crate are test material and must never be
//! installed in a production image.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use p256::pkcs8::EncodePrivateKey;
use rcgen::KeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};

pub mod nsm;
pub mod server;

/// Fail closed when authenticated evidence is not bound to the caller's
/// challenge/report data.
pub fn ensure_report_data(actual: &[u8], expected: &[u8]) -> Result<()> {
    anyhow::ensure!(actual == expected, "mock attestation report_data mismatch");
    Ok(())
}
pub mod sev_snp;
pub mod tdx;
pub mod tpm;

pub const MOCK_SEED_LEN: usize = 32;

/// Returns whether the simulated platform provides its own TPM device.
pub fn platform_provides_tpm(platform: dstack_types::TeeVariant) -> bool {
    matches!(
        platform,
        dstack_types::TeeVariant::DstackGcpTdx | dstack_types::TeeVariant::DstackAwsNitroTpm
    )
}

pub fn parse_seed(value: &str) -> Result<[u8; MOCK_SEED_LEN]> {
    let bytes = hex::decode(value).context("mock attestation seed must be hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("mock attestation seed must be 32 bytes"))
}

pub fn random_seed() -> [u8; MOCK_SEED_LEN] {
    rand::random()
}

pub(crate) fn p256_key(seed: &[u8; 32], label: &str) -> Result<KeyPair> {
    for counter in 0u32.. {
        let bytes = Sha256::new()
            .chain_update(b"dstack-mock-p256-v1")
            .chain_update(seed)
            .chain_update(label)
            .chain_update(counter.to_be_bytes())
            .finalize();
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&bytes) {
            return Ok(KeyPair::from_pem(&key.to_pkcs8_pem(Default::default())?)?);
        }
    }
    unreachable!()
}

pub(crate) fn p384_key(seed: &[u8; 32], label: &str) -> Result<KeyPair> {
    for counter in 0u32.. {
        let bytes = Sha384::new()
            .chain_update(b"dstack-mock-p384-v1")
            .chain_update(seed)
            .chain_update(label)
            .chain_update(counter.to_be_bytes())
            .finalize();
        if let Ok(key) = p384::ecdsa::SigningKey::from_slice(&bytes) {
            return Ok(KeyPair::from_pem(&key.to_pkcs8_pem(Default::default())?)?);
        }
    }
    unreachable!()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetManifest {
    pub version: u32,
    pub tdx_root_ca: PathBuf,
    pub tpm_root_ca: PathBuf,
    pub nsm_root_ca: PathBuf,
    pub sev_snp_milan_root_ca: PathBuf,
    pub sev_snp_genoa_root_ca: PathBuf,
    pub sev_snp_turin_root_ca: PathBuf,
}

impl AssetManifest {
    pub fn write_to(&self, output: &Path) -> Result<()> {
        fs_err::write(
            output.join("manifest.json"),
            serde_json::to_vec_pretty(self).context("failed to serialize asset manifest")?,
        )?;
        Ok(())
    }
}

pub fn generate_assets(output: &Path) -> Result<AssetManifest> {
    generate_assets_from_seed(output, random_seed(), "http://127.0.0.1:8088")
}

pub fn generate_assets_from_seed(
    output: &Path,
    seed: [u8; 32],
    base_url: &str,
) -> Result<AssetManifest> {
    fs_err::create_dir_all(output)?;
    let state = server::MockCollateralState::from_seed(seed, base_url)?;
    state.write_roots(output)?;
    let tdx = PathBuf::from("tdx-root-ca.pem");
    let tpm = PathBuf::from("tpm-root-ca.pem");
    let nsm = PathBuf::from("nsm-root-ca.pem");
    let milan = PathBuf::from("sev-snp-root-ca.pem");
    let genoa = milan.clone();
    let turin = milan.clone();
    let manifest = AssetManifest {
        version: 1,
        tdx_root_ca: tdx,
        tpm_root_ca: tpm,
        nsm_root_ca: nsm,
        sev_snp_milan_root_ca: milan,
        sev_snp_genoa_root_ca: genoa,
        sev_snp_turin_root_ca: turin,
    };
    manifest.write_to(output)?;
    fs_err::write(
        output.join("tee-simulator.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "platform": "dstack-tdx", "mock_attestation_seed": hex::encode(seed), "collateral_base_url": base_url
        }))?,
    )?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_all_platform_roots() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = generate_assets(dir.path()).unwrap();
        for path in [
            manifest.tdx_root_ca,
            manifest.tpm_root_ca,
            manifest.nsm_root_ca,
            manifest.sev_snp_milan_root_ca,
            manifest.sev_snp_genoa_root_ca,
            manifest.sev_snp_turin_root_ca,
        ] {
            assert!(dir.path().join(path).exists());
        }
    }

    #[test]
    fn identifies_platforms_that_provide_a_tpm() {
        assert!(platform_provides_tpm(
            dstack_types::TeeVariant::DstackGcpTdx
        ));
        assert!(platform_provides_tpm(
            dstack_types::TeeVariant::DstackAwsNitroTpm
        ));
        assert!(!platform_provides_tpm(dstack_types::TeeVariant::DstackTdx));
    }
}
