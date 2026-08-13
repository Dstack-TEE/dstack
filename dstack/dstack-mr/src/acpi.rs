// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! QEMU-compatible ACPI table generation for TDX measurement.

use anyhow::{bail, Context, Result};
use qemu_acpi::{MachineConfig, QemuVersion};

use crate::Machine;

#[derive(Debug, Clone)]
pub struct Tables {
    pub tables: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub loader: Vec<u8>,
}

impl Machine<'_> {
    pub fn build_tables(&self) -> Result<Tables> {
        if self.swtpm {
            bail!("swtpm measurement is not supported");
        }
        let options = self
            .versioned_options()
            .context("failed to get QEMU-versioned options")?;
        match self.host_share_mode.as_str() {
            "" | "9p" | "vvfat" | "vhd" => {}
            value => bail!("invalid shared disk mode: {value}"),
        }
        let config = MachineConfig {
            qemu_version: QemuVersion::new(options.version.0, options.version.1, options.version.2),
            cpu_count: self.cpu_count,
            memory_size: self.memory_size,
            pic: options.pic,
            smm: self.smm,
            hugepages: self.hugepages,
            num_gpus: self.num_gpus,
            num_nvswitches: self.num_nvswitches,
            num_nics: self.num_nics,
            num_verity_volumes: self.num_verity_volumes,
            hotplug_off: self.hotplug_off,
            root_verity: self.root_verity,
            pci_hole64_size: self.pci_hole64_size,
        };
        let blobs = qemu_acpi::build(&config).context("failed to generate QEMU ACPI tables")?;
        Ok(Tables {
            tables: blobs.tables,
            rsdp: blobs.rsdp,
            loader: blobs.loader,
        })
    }
}
