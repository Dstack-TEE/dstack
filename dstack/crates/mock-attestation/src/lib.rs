// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Development-only attestation PKI and evidence generation.
//!
//! Private keys produced by this crate are test material and must never be
//! installed in a production image.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, CertifiedKey, IsCa, KeyPair};
use serde::{Deserialize, Serialize};

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
    fs_err::create_dir_all(output)?;
    let tdx = write_ca(output, "tdx", "Mock Intel SGX Root CA")?;
    let tpm = write_ca(output, "tpm", "Mock TPM Root CA")?;
    let nsm = write_ca(output, "nsm", "Mock AWS Nitro Enclaves Root CA")?;
    let milan = write_ca(output, "sev-snp-milan", "Mock AMD Milan ARK")?;
    let genoa = write_ca(output, "sev-snp-genoa", "Mock AMD Genoa ARK")?;
    let turin = write_ca(output, "sev-snp-turin", "Mock AMD Turin ARK")?;
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
    Ok(manifest)
}

fn write_ca(output: &Path, name: &str, common_name: &str) -> Result<PathBuf> {
    let dir = output.join(name);
    fs_err::create_dir_all(&dir)?;
    let CertifiedKey { cert, key_pair } = make_ca(common_name)?;
    let cert_path = dir.join("root-ca.pem");
    fs_err::write(&cert_path, cert.pem())?;
    fs_err::write(dir.join("root-ca-key.pem"), key_pair.serialize_pem())?;
    Ok(cert_path
        .strip_prefix(output)
        .unwrap_or(&cert_path)
        .to_path_buf())
}

fn make_ca(common_name: &str) -> Result<CertifiedKey> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key)?;
    Ok(CertifiedKey {
        cert,
        key_pair: key,
    })
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
}
