// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

//! Assembly of the ACPI table blob from generated records only.

use crate::{
    dsdt, fixed_tables, srat, AcpiBlobs, Compatibility, Error, MachineConfig, TABLE_BLOB_SIZE,
};

pub(crate) fn build(config: &MachineConfig) -> Result<AcpiBlobs, Error> {
    let mut tables = fixed_tables::facs();
    tables.extend(dsdt::table(config)?);

    let fadt_offset = tables.len() as u32;
    tables.extend(fixed_tables::fadt(config.smm, config.cpu_count));
    let madt_offset = tables.len() as u32;
    let legacy_irq_overrides = matches!(
        config.qemu_version.compatibility(),
        Some(Compatibility::V8 | Compatibility::V9Pre92)
    );
    tables.extend(fixed_tables::madt(
        config.cpu_count,
        config.pic,
        legacy_irq_overrides,
    ));
    let srat_offset = config.hugepages.then_some(tables.len() as u32);
    if config.hugepages {
        tables.extend(srat::build(
            config.cpu_count,
            config.memory_size,
            config.pci_hole64_size,
        ));
    }
    let mcfg_offset = tables.len() as u32;
    tables.extend(fixed_tables::mcfg());
    let waet_offset = tables.len() as u32;
    tables.extend(fixed_tables::waet());

    let mut entries = vec![fadt_offset, madt_offset];
    entries.extend(srat_offset);
    entries.extend([mcfg_offset, waet_offset]);
    tables.extend(fixed_tables::rsdt(&entries));
    tables.resize(tables.len().div_ceil(TABLE_BLOB_SIZE) * TABLE_BLOB_SIZE, 0);
    crate::fw_cfg::finish(tables)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::QemuVersion;

    #[test]
    fn baseline_matches_qemu_from_scratch() -> Result<(), Error> {
        let config = MachineConfig {
            qemu_version: QemuVersion::new(11, 1, 0),
            cpu_count: 1,
            memory_size: 2 << 30,
            pic: false,
            smm: false,
            hugepages: false,
            num_gpus: 0,
            num_nvswitches: 0,
            num_nics: 0,
            num_verity_volumes: 0,
            hotplug_off: false,
            root_verity: true,
            pci_hole64_size: None,
        };
        let actual = build(&config)?;
        let expected = include_bytes!("../fixtures/qemu-11.1-q35-base.bin");
        assert_eq!(&actual.tables[..expected.len()], *expected);
        assert!(actual.tables[expected.len()..]
            .iter()
            .all(|byte| *byte == 0));
        Ok(())
    }
}
