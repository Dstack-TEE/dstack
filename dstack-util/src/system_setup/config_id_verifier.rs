// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use dstack_attest::attestation::{Attestation, AttestationMode, AttestationQuote};
use dstack_types::{
    mr_config::{MrConfig, MrConfigV3},
    shared_filenames::{HOST_SHARED_DIR, SYS_CONFIG},
    KeyProviderKind, SysConfig,
};
use tracing::info;

#[derive(Clone, Copy)]
struct ExpectedMrConfig<'a> {
    compose_hash: &'a [u8; 32],
    app_id: &'a [u8; 20],
    instance_id: &'a [u8],
    key_provider: KeyProviderKind,
    key_provider_id: &'a [u8],
}

fn read_mr_config_id() -> Result<[u8; 48]> {
    let quote = tdx_attest::get_quote(&[0u8; 64]).context("Failed to get quote")?;
    let quote = dcap_qvl::quote::Quote::parse(&quote).context("Failed to parse quote")?;
    let configid = quote
        .report
        .as_td10()
        .context("Failed to get TD10 report")?
        .mr_config_id;
    Ok(configid)
}

fn read_mr_config_document() -> Result<String> {
    let path = std::path::Path::new(HOST_SHARED_DIR).join(SYS_CONFIG);
    let content = fs_err::read_to_string(path).context("Failed to read sys-config")?;
    let sys_config: SysConfig =
        serde_json::from_str(&content).context("Failed to parse sys-config")?;
    if let Some(mr_config) = sys_config.mr_config {
        return Ok(mr_config);
    }
    serde_json::from_str::<serde_json::Value>(&sys_config.vm_config)
        .ok()
        .and_then(|value| {
            value
                .get("mr_config")
                .and_then(|value| value.as_str())
                .map(ToString::to_string)
        })
        .context("mr_config is required")
}

fn read_snp_host_data() -> Result<[u8; 32]> {
    let attestation = Attestation::quote(&[0u8; 64]).context("Failed to get SNP report")?;
    let AttestationQuote::DstackAmdSevSnp(quote) = attestation.quote else {
        bail!("attestation mode is not AMD SEV-SNP");
    };
    let parsed = dstack_attest::amd_sev_snp::parse_amd_snp_report(&quote.report)
        .context("Failed to parse SNP report")?;
    Ok(parsed.host_data)
}

/// Verify the mr_config_id matches the expected value
///
/// Configuration ID format
/// The mr_config_id is a 48 bytes value in the following format:
/// The first byte is the version of the format.
/// When version is 1, the next 32 bytes are the compose hash.
/// When version is 2, the next 32 bytes are the keccak256 hash of the instance info.
/// Where the instance info is a concatenated bytes of the following fields:
/// - compose_hash: [u8; 32]
/// - app_id: [u8; 20]
/// - key_provider_type: u8 // 0: none, 1: local, 2: kms, 3: tpm
/// - key_provider_id: [u8] // the ca pubkey for KMS or the MR enclave for local-sgx provider, empty for none
pub fn verify_mr_config_id(
    compose_hash: &[u8; 32],
    app_id: &[u8; 20],
    instance_id: &[u8],
    key_provider: KeyProviderKind,
    key_provider_id: &[u8],
) -> Result<()> {
    let mode = AttestationMode::detect().context("Failed to detect attestation mode")?;
    let expected = ExpectedMrConfig {
        compose_hash,
        app_id,
        instance_id,
        key_provider,
        key_provider_id,
    };
    verify_mr_config_id_for_mode(mode, expected)
}

fn verify_mr_config_id_for_mode(
    mode: AttestationMode,
    expected: ExpectedMrConfig<'_>,
) -> Result<()> {
    match mode {
        AttestationMode::DstackAmdSevSnp => verify_snp_mr_config(expected),
        _ => verify_tdx_mr_config_id(expected),
    }
}

fn verify_tdx_mr_config_id(expected: ExpectedMrConfig<'_>) -> Result<()> {
    let read_mr_config_id = read_mr_config_id().context("Failed to read mr_config_id")?;
    info!("mr_config_id: {}", hex::encode(read_mr_config_id));
    let mr_config_document = if read_mr_config_id[0] == 3 {
        Some(read_mr_config_document().context("Failed to read mr_config")?)
    } else {
        None
    };
    verify_tdx_mr_config_id_value(read_mr_config_id, mr_config_document.as_deref(), expected)
}

fn verify_tdx_mr_config_id_value(
    read_mr_config_id: [u8; 48],
    mr_config_document: Option<&str>,
    expected: ExpectedMrConfig<'_>,
) -> Result<()> {
    if read_mr_config_id == [0u8; 48] {
        return Ok(());
    }
    let expected_mr_config_id = match read_mr_config_id[0] {
        1 => MrConfig::V1 {
            compose_hash: expected.compose_hash,
        }
        .to_mr_config_id(),
        2 => MrConfig::V2 {
            compose_hash: expected.compose_hash,
            app_id: expected.app_id,
            key_provider: expected.key_provider,
            key_provider_id: expected.key_provider_id,
        }
        .to_mr_config_id(),
        3 => {
            let mr_config_document =
                mr_config_document.context("mr_config is required for TDX MR_CONFIG_ID v3")?;
            verify_mr_config_v3_document(mr_config_document, expected)?;
            MrConfigV3::tdx_mr_config_id_from_document(mr_config_document)
        }
        _ => bail!("Invalid mr_config_id version"),
    };
    if expected_mr_config_id != read_mr_config_id {
        bail!("Invalid mr_config_id");
    }
    Ok(())
}

fn verify_snp_mr_config(expected: ExpectedMrConfig<'_>) -> Result<()> {
    let mr_config_document = read_mr_config_document().context("Failed to read SNP mr_config")?;
    verify_mr_config_v3_document(&mr_config_document, expected)?;
    let read_host_data = read_snp_host_data().context("Failed to read SNP HOST_DATA")?;
    info!("snp host_data: {}", hex::encode(read_host_data));
    if MrConfigV3::snp_host_data_from_document(&mr_config_document) != read_host_data {
        bail!("Invalid SNP HOST_DATA");
    }
    Ok(())
}

fn verify_mr_config_v3_document(
    mr_config_document: &str,
    expected: ExpectedMrConfig<'_>,
) -> Result<MrConfigV3> {
    let mr_config =
        MrConfigV3::from_document(mr_config_document).context("Invalid mr_config document")?;
    if mr_config.version != 3 {
        bail!("mr_config version must be 3");
    }
    if mr_config.compose_hash.as_slice() != expected.compose_hash {
        bail!("Invalid mr_config compose_hash");
    }
    if mr_config.app_id.as_slice() != expected.app_id {
        bail!("Invalid mr_config app_id");
    }
    if mr_config.instance_id.as_slice() != expected.instance_id {
        bail!("Invalid mr_config instance_id");
    }
    if mr_config.key_provider != expected.key_provider {
        bail!("Invalid mr_config key_provider");
    }
    if mr_config.key_provider_id.as_slice() != expected.key_provider_id {
        bail!("Invalid mr_config key_provider_id");
    }
    Ok(mr_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tdx_mr_config_id_v1_accepts_expected_value() {
        let compose_hash = [0x11u8; 32];
        let mr_config = MrConfig::V1 {
            compose_hash: &compose_hash,
        };
        assert_eq!(mr_config.to_mr_config_id()[0], 1);
    }

    #[test]
    fn tdx_mr_config_id_v3_accepts_document_value() -> Result<()> {
        let compose_hash = [0x22u8; 32];
        let app_id = [0x11u8; 20];
        let instance_id = [0x44u8; 20];
        let key_provider_id = [0x33u8; 32];
        let mr_config = MrConfigV3::new(
            app_id.to_vec(),
            compose_hash.to_vec(),
            KeyProviderKind::Kms,
            key_provider_id.to_vec(),
            instance_id.to_vec(),
        );
        let document = mr_config.to_canonical_json();
        let expected = ExpectedMrConfig {
            compose_hash: &compose_hash,
            app_id: &app_id,
            instance_id: &instance_id,
            key_provider: KeyProviderKind::Kms,
            key_provider_id: &key_provider_id,
        };

        verify_tdx_mr_config_id_value(mr_config.to_tdx_mr_config_id(), Some(&document), expected)
    }

    #[test]
    fn mr_config_v3_document_must_match_expected_app_info() {
        let compose_hash = [0x22u8; 32];
        let app_id = [0x11u8; 20];
        let instance_id = [0x44u8; 20];
        let key_provider_id = [0x33u8; 32];
        let document = MrConfigV3::new(
            app_id.to_vec(),
            compose_hash.to_vec(),
            KeyProviderKind::Kms,
            key_provider_id.to_vec(),
            instance_id.to_vec(),
        )
        .to_canonical_json();
        let wrong_app_id = [0x12u8; 20];
        let expected = ExpectedMrConfig {
            compose_hash: &compose_hash,
            app_id: &wrong_app_id,
            instance_id: &instance_id,
            key_provider: KeyProviderKind::Kms,
            key_provider_id: &key_provider_id,
        };

        match verify_mr_config_v3_document(&document, expected) {
            Ok(_) => panic!("mismatched app_id must reject"),
            Err(err) => assert!(err.to_string().contains("Invalid mr_config app_id")),
        }
    }
}
