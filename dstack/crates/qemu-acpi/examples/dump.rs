// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::str::FromStr;

use qemu_acpi::{build, MachineConfig, QemuVersion};

fn optional<T: FromStr>(args: &mut impl Iterator<Item = String>, default: T) -> Result<T, String> {
    match args.next() {
        Some(value) => value.parse().map_err(|_| format!("invalid value: {value}")),
        None => Ok(default),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let nics: u32 = optional(&mut args, 1)?;
    let cpus: u32 = optional(&mut args, 1)?;
    let version = QemuVersion::from_str(&optional::<String>(&mut args, "11.1.0".into())?)
        .map_err(|error| format!("invalid QEMU version: {error}"))?;
    let gpus = optional(&mut args, 0)?;
    let nvswitches = optional(&mut args, 0)?;
    let hugepages = optional::<u8>(&mut args, 0)? == 1;
    let root_verity = optional::<u8>(&mut args, 1)? != 0;
    let hotplug_off = optional::<u8>(&mut args, 0)? == 1;
    let smm = optional::<u8>(&mut args, 0)? == 1;
    let hole = optional::<u64>(&mut args, 0)?;
    let memory_size = optional(&mut args, 2u64 << 30)?;
    let volumes = optional(&mut args, 0)?;
    let pic = optional::<u8>(&mut args, 0)? == 1;
    let blobs = build(&MachineConfig {
        qemu_version: version,
        cpu_count: cpus,
        memory_size,
        pic,
        smm,
        hugepages,
        num_gpus: gpus,
        num_nvswitches: nvswitches,
        num_nics: nics,
        num_verity_volumes: volumes,
        hotplug_off,
        root_verity,
        pci_hole64_size: (hole != 0).then_some(hole),
    })?;
    std::fs::write("/tmp/rust.bin", blobs.tables)?;
    std::fs::write("/tmp/rust-loader.bin", blobs.loader)?;
    std::fs::write("/tmp/rust-rsdp.bin", blobs.rsdp)?;
    Ok(())
}
