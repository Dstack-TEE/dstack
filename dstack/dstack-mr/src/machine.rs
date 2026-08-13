// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::acpi::Tables;
use crate::tdvf::Tdvf;
use crate::util::debug_print_log;
use crate::{kernel, OvmfVariant, RtmrLogs, TdxMeasurements};
use crate::{measure_log, measure_sha384};
use anyhow::{bail, Context, Result};
use fs_err as fs;
use log::debug;

#[derive(Debug, bon::Builder)]
pub struct Machine<'a> {
    pub cpu_count: u32,
    pub memory_size: u64,
    pub firmware: &'a str,
    pub kernel: &'a str,
    pub initrd: &'a str,
    pub kernel_cmdline: &'a str,
    pub two_pass_add_pages: Option<bool>,
    pub pic: Option<bool>,
    pub qemu_version: Option<String>,
    #[builder(default = false)]
    pub smm: bool,
    pub pci_hole64_size: Option<u64>,
    pub hugepages: bool,
    pub num_gpus: u32,
    pub num_nvswitches: u32,
    /// Number of virtio-net NICs. Each NIC contributes a PCI device to the
    /// ACPI/DSDT layout measured into RTMR0. Defaults to 1 so callers that
    /// predate this field keep the historical single-NIC layout.
    #[builder(default = 1)]
    pub num_nics: u32,
    /// Number of virtio-blk verity volumes attached before the NICs.
    #[builder(default)]
    pub num_verity_volumes: u32,
    /// Whether QEMU attaches a tpm-tis device backed by swtpm.
    #[builder(default)]
    pub swtpm: bool,
    pub hotplug_off: bool,
    pub root_verity: bool,
    #[builder(default)]
    pub host_share_mode: String,
    /// Selects which OVMF measurement event layout to expect.
    /// Defaults to the supported pre-202505 layout.
    #[builder(default)]
    pub ovmf_variant: OvmfVariant,
}

fn parse_version_tuple(v: &str) -> Result<(u32, u32, u32)> {
    let mut parts = v.split('.');
    let major = parts
        .next()
        .context("Version string must have exactly 3 parts (major.minor.patch)")?
        .parse::<u32>()
        .context("Invalid version number")?;
    let minor = parts
        .next()
        .context("Version string must have exactly 3 parts (major.minor.patch)")?
        .parse::<u32>()
        .context("Invalid version number")?;
    let patch = parts
        .next()
        .context("Version string must have exactly 3 parts (major.minor.patch)")?
        .parse::<u32>()
        .context("Invalid version number")?;
    if parts.next().is_some() {
        bail!("Version string must have exactly 3 parts (major.minor.patch)");
    }
    Ok((major, minor, patch))
}

impl Machine<'_> {
    pub fn versioned_options(&self) -> Result<VersionedOptions> {
        let version = match &self.qemu_version {
            Some(v) => Some(parse_version_tuple(v).context("Failed to parse QEMU version")?),
            None => None,
        };
        let default_pic;
        let default_two_pass;
        let version = version.unwrap_or((9, 1, 0));
        if version < (8, 0, 0) {
            bail!("Unsupported QEMU version: {version:?}");
        }
        if ((8, 0, 0)..(9, 0, 0)).contains(&version) {
            default_pic = true;
            default_two_pass = true;
        } else {
            default_pic = false;
            default_two_pass = false;
        };
        Ok(VersionedOptions {
            version,
            pic: self.pic.unwrap_or(default_pic),
            two_pass_add_pages: self.two_pass_add_pages.unwrap_or(default_two_pass),
        })
    }
}

pub struct VersionedOptions {
    pub version: (u32, u32, u32),
    pub pic: bool,
    pub two_pass_add_pages: bool,
}

#[derive(Debug, Clone)]
pub struct TdxMeasurementDetails {
    pub measurements: TdxMeasurements,
    pub rtmr_logs: RtmrLogs,
    pub acpi_tables: Tables,
}

impl Machine<'_> {
    pub fn measure(&self) -> Result<TdxMeasurements> {
        self.measure_with_logs().map(|details| details.measurements)
    }

    pub fn measure_with_logs(&self) -> Result<TdxMeasurementDetails> {
        debug!("measuring machine: {self:#?}");
        let fw_data = fs::read(self.firmware)?;
        let kernel_data = fs::read(self.kernel)?;
        let initrd_data = fs::read(self.initrd)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;

        let mrtd = tdvf.mrtd(self).context("Failed to compute MR TD")?;

        let (rtmr0_log, acpi_tables) = tdvf
            .rtmr0_log(self)
            .context("Failed to compute RTMR0 log")?;
        debug_print_log("RTMR0", &rtmr0_log);
        let rtmr0 = measure_log(&rtmr0_log);

        let rtmr1_log = kernel::rtmr1_log(
            &kernel_data,
            initrd_data.len() as u32,
            self.memory_size,
            0x28000,
        )?;
        debug_print_log("RTMR1", &rtmr1_log);
        let rtmr1 = measure_log(&rtmr1_log);

        let rtmr2_log = vec![
            kernel::measure_cmdline(self.kernel_cmdline),
            measure_sha384(&initrd_data),
        ];
        debug_print_log("RTMR2", &rtmr2_log);
        let rtmr2 = measure_log(&rtmr2_log);

        Ok(TdxMeasurementDetails {
            measurements: TdxMeasurements {
                mrtd,
                rtmr0,
                rtmr1,
                rtmr2,
            },
            rtmr_logs: [rtmr0_log, rtmr1_log, rtmr2_log],
            acpi_tables,
        })
    }
}
