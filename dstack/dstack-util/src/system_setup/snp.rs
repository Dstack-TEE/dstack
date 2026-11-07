// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use dstack_types::{KeyProviderKind, SnpSealingParameters};
use zeroize::Zeroizing;

use super::{detect_tee_variant, parse_dstack_options, AppInfo, Command, Stage0, TeeVariant};

const SEALING_VERSION: u32 = 1;

fn parameters_for_boot(
    stored: Option<SnpSealingParameters>,
    disk_initialized: bool,
    initial_tcb: impl FnOnce() -> Result<u64>,
) -> Result<SnpSealingParameters> {
    if let Some(parameters) = stored {
        if parameters.version != SEALING_VERSION {
            bail!(
                "unsupported SNP sealing parameter version: {}",
                parameters.version
            );
        }
        return Ok(parameters);
    }
    if disk_initialized {
        bail!("snp sealing parameters are missing for an existing encrypted disk");
    }
    Ok(SnpSealingParameters {
        version: SEALING_VERSION,
        tcb_version: initial_tcb()?,
    })
}

impl Stage0<'_> {
    pub(super) async fn get_snp_seed(&self, app_info: &mut AppInfo) -> Result<Zeroizing<[u8; 32]>> {
        if detect_tee_variant()? != TeeVariant::DstackAmdSevSnp {
            bail!("the SEV-SNP key provider requires an AMD SEV-SNP guest");
        }
        // HOST_DATA is host-supplied. The measured OS must validate its binding
        // to the actual app/config before deriving or using a sealing seed.
        self.verify_app_config(app_info, KeyProviderKind::SevSnp, &[])?;
        if !parse_dstack_options(&self.shared)?.storage_encrypted {
            bail!("the SEV-SNP key provider requires encrypted storage");
        }
        let status = Command::new("cryptsetup")
            .arg("isLuks")
            .arg(&self.args.device)
            .status()
            .context("failed to inspect disk before SNP sealing initialization")?;
        let disk_initialized = match status.code() {
            Some(0) => true,
            Some(1) => false,
            _ => bail!("failed to inspect disk before SNP sealing initialization: {status}"),
        };
        let parameters = parameters_for_boot(
            app_info.instance_info.snp_sealing,
            disk_initialized,
            sev_snp_attest::sealing::initial_tcb_version,
        )?;
        app_info.instance_info.snp_sealing = Some(parameters);

        // The share is read-only in the guest. Use the existing per-VM,
        // acknowledged persistence operation, and stop if it cannot persist.
        // No key material is sent to the host; only public derivation metadata.
        self.shared
            .sys_config
            .host_api_url
            .as_ref()
            .context("snp sealing requires host API persistence for instance metadata")?;
        self.vmm
            .notify(
                "instance.info",
                &serde_json::to_string(&app_info.instance_info)?,
            )
            .await
            .context("failed to persist SNP sealing parameters before disk unlock")?;
        sev_snp_attest::sealing::derive_sealing_seed(parameters.tcb_version)
            .context("failed to derive SNP sealing seed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_initial_tcb_on_later_boots() {
        let stored = SnpSealingParameters {
            version: 1,
            tcb_version: 0x0101,
        };
        let actual =
            parameters_for_boot(Some(stored), true, || panic!("must not select a new TCB"));
        assert_eq!(actual.unwrap(), stored);
    }

    #[test]
    fn initializes_only_a_new_disk() {
        let parameters = parameters_for_boot(None, false, || Ok(0x0202)).unwrap();
        assert_eq!(
            parameters,
            SnpSealingParameters {
                version: 1,
                tcb_version: 0x0202
            }
        );
        assert!(
            parameters_for_boot(None, true, || panic!("must not replace missing metadata"))
                .is_err()
        );
    }

    #[test]
    fn rejects_unknown_policy_and_derivation_errors() {
        let stored = SnpSealingParameters {
            version: 2,
            tcb_version: 1,
        };
        assert!(parameters_for_boot(Some(stored), true, || panic!(
            "must not replace unknown policy"
        ))
        .is_err());
        assert!(parameters_for_boot(None, false, || bail!("unsupported platform")).is_err());
    }
}
