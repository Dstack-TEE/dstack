//! This module provides functionality to generate ACPI tables for QEMU,
//! translated from an original Go implementation.

use anyhow::{bail, Context, Result};
use log::debug;

use crate::Machine;

const LDR_LENGTH: usize = 4096;
const FIXED_STRING_LEN: usize = 56;

pub struct Tables {
    pub tables: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub loader: Vec<u8>,
}

impl Machine<'_> {
    fn create_tables(&self) -> Result<Vec<u8>> {
        if self.cpu_count == 0 {
            bail!("cpuCount must be greater than 0");
        }
        let mem_size_mb = self.memory_size / (1024 * 1024);

        // Dummy disk and shared directory. Use as placeholders for the qemu arguments.
        let dummy_disk = "/bin/sh";
        let shared_dir = "/bin";

        // Prepare the command arguments
        let mut cmd = std::process::Command::new("dstack-acpi-tables");
        cmd.args([
            "-cpu",
            "qemu64",
            "-smp",
            &self.cpu_count.to_string(),
            "-m",
            &format!("{mem_size_mb}M"),
            "-nographic",
            "-nodefaults",
            "-serial",
            "stdio",
            "-bios",
            self.firmware,
            "-kernel",
            self.kernel,
            "-initrd",
            dummy_disk,
            "-drive",
            &format!("file={dummy_disk},if=none,id=hd1,format=raw,readonly=on"),
            "-device",
            "virtio-blk-pci,drive=hd1",
            "-netdev",
            "user,id=net0",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-object",
            "tdx-guest,id=tdx",
            "-device",
            "vhost-vsock-pci,guest-cid=3",
            "-virtfs",
            &format!(
                "local,path={shared_dir},mount_tag=host-shared,readonly=on,security_model=none,id=virtfs0",
            ),
        ]);

        if self.root_verity {
            cmd.args([
                "-drive",
                &format!("file={dummy_disk},if=none,id=hd0,format=raw,readonly=on"),
                "-device",
                "virtio-blk-pci,drive=hd0",
            ]);
        } else {
            cmd.args(["-cdrom", dummy_disk]);
        }

        let mut machine =
            "q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off".to_string();
        if self.smm {
            machine.push_str(",smm=on");
        } else {
            machine.push_str(",smm=off");
        }
        if self.pic {
            machine.push_str(",pic=on");
        } else {
            machine.push_str(",pic=off");
        }
        cmd.args(["-machine", &machine]);
        if self.hugepages {
            let cpu_end = self.cpu_count - 1;
            cmd.args([
                "-numa",
                &format!("node,nodeid=0,cpus=0-{cpu_end},memdev=mem0"),
                "-object",
                &format!("memory-backend-file,id=mem0,size={mem_size_mb}M,mem-path=/dev/hugepages,share=on,prealloc=no,host-nodes=0,policy=bind"),
            ]);
        }
        let mut port_num = 0;
        if self.num_gpus > 0 {
            cmd.args(["-object", "iommufd,id=iommufd0"]);
            let bus = if self.hugepages {
                cmd.args([
                    "-device",
                    "pxb-pcie,id=pcie.node0,bus=pcie.0,addr=10,numa_node=0,bus_nr=5",
                ]);
                "pcie.node0"
            } else {
                "pcie.0"
            };
            for _ in 0..self.num_gpus {
                cmd.args([
                    "-device",
                    &format!("pcie-root-port,id=pci.{port_num},bus={bus},chassis={port_num}"),
                    "-device",
                    &format!("vfio-pci,host=00:00.0,bus=pci.{port_num},iommufd=iommufd0"),
                ]);
                port_num += 1;
            }
        }

        for _ in 0..self.num_nvswitches {
            cmd.args([
                "-device",
                &format!("pcie-root-port,id=pci.{port_num},bus=pcie.0,chassis={port_num}"),
                "-device",
                &format!("vfio-pci,host=00:00.0,bus=pci.{port_num},iommufd=iommufd0"),
            ]);
            port_num += 1;
        }

        if self.hotplug_off {
            cmd.args([
                "-global",
                "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off",
            ]);
        }
        if let Some(pci_hole64_size) = self.pci_hole64_size {
            cmd.args([
                "-global",
                &format!("q35-pcihost.pci-hole64-size=0x{:x}", pci_hole64_size),
            ]);
        }

        debug!("qemu command: {cmd:?}");

        // Execute the command and capture output
        let output = cmd
            .output()
            .context("failed to execute dstack-acpi-tables")?;

        // Check if the command was successful
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("dstack-acpi-tables failed: {stderr}");
        }
        Ok(output.stdout)
    }

    pub fn build_tables(&self) -> Result<Tables> {
        let tpl = self.create_tables()?;
        // Find all required ACPI tables
        let (dsdt_offset, dsdt_csum, dsdt_len) = find_acpi_table(&tpl, "DSDT")?;
        let (facp_offset, facp_csum, facp_len) = find_acpi_table(&tpl, "FACP")?;
        let (apic_offset, apic_csum, apic_len) = find_acpi_table(&tpl, "APIC")?;
        let (mcfg_offset, mcfg_csum, mcfg_len) = find_acpi_table(&tpl, "MCFG")?;
        let (waet_offset, waet_csum, waet_len) = find_acpi_table(&tpl, "WAET")?;
        let (rsdt_offset, rsdt_csum, rsdt_len) = find_acpi_table(&tpl, "RSDT")?;

        // Generate RSDP
        let mut rsdp = Vec::with_capacity(20);
        rsdp.extend_from_slice(b"RSD PTR "); // Signature
        rsdp.push(0x00); // Checksum placeholder
        rsdp.extend_from_slice(b"BOCHS "); // OEM ID
        rsdp.push(0x00); // Revision
        rsdp.extend_from_slice(&rsdt_offset.to_le_bytes()); // RSDT Address

        // Generate table loader commands
        let mut ldr = TableLoader::new();
        ldr.append(LoaderCmd::Allocate {
            file: "etc/acpi/rsdp",
            alignment: 16,
            zone: 2,
        });
        ldr.append(LoaderCmd::Allocate {
            file: "etc/acpi/tables",
            alignment: 64,
            zone: 1,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: dsdt_csum,
            start: dsdt_offset,
            length: dsdt_len,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: facp_offset + 36,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: facp_offset + 40,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: facp_offset + 140,
            pointer_size: 8,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: facp_csum,
            start: facp_offset,
            length: facp_len,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: apic_csum,
            start: apic_offset,
            length: apic_len,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: mcfg_csum,
            start: mcfg_offset,
            length: mcfg_len,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: waet_csum,
            start: waet_offset,
            length: waet_len,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: rsdt_offset + 36,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: rsdt_offset + 40,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: rsdt_offset + 44,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: rsdt_offset + 48,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: rsdt_csum,
            start: rsdt_offset,
            length: rsdt_len,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/rsdp",
            pointee_file: "etc/acpi/tables",
            pointer_offset: 16,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/rsdp",
            result_offset: 8,
            start: 0,
            length: 20,
        });
        // 8. Pad the loader command blob to the required length
        if ldr.buffer.len() < LDR_LENGTH {
            ldr.buffer.resize(LDR_LENGTH, 0);
        }

        Ok(Tables {
            tables: tpl,
            rsdp,
            loader: ldr.buffer,
        })
    }
}

/// An enum to represent the different QEMU loader commands in a type-safe way.
#[derive(Debug)]
enum LoaderCmd<'a> {
    Allocate {
        file: &'a str,
        alignment: u32,
        zone: u8,
    },
    AddPtr {
        pointer_file: &'a str,
        pointee_file: &'a str,
        pointer_offset: u32,
        pointer_size: u8,
    },
    AddChecksum {
        file: &'a str,
        result_offset: u32,
        start: u32,
        length: u32,
    },
}

struct TableLoader {
    buffer: Vec<u8>,
}

impl TableLoader {
    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(LDR_LENGTH),
        }
    }
    fn append(&mut self, cmd: LoaderCmd) {
        qemu_loader_append(&mut self.buffer, cmd);
    }
}

/// Appends a fixed-length, null-padded string to the data buffer.
fn append_fixed_string(data: &mut Vec<u8>, s: &str) {
    let mut s_bytes = s.as_bytes().to_vec();
    s_bytes.resize(FIXED_STRING_LEN, 0);
    data.extend_from_slice(&s_bytes);
}

/// Appends a serialized QEMU loader command to the data buffer.
fn qemu_loader_append(data: &mut Vec<u8>, cmd: LoaderCmd) {
    match cmd {
        LoaderCmd::Allocate {
            file,
            alignment,
            zone,
        } => {
            data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
            append_fixed_string(data, file);
            data.extend_from_slice(&alignment.to_le_bytes());
            data.push(zone);
            data.resize(data.len() + 63, 0); // Padding
        }
        LoaderCmd::AddPtr {
            pointer_file,
            pointee_file,
            pointer_offset,
            pointer_size,
        } => {
            data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
            append_fixed_string(data, pointer_file);
            append_fixed_string(data, pointee_file);
            data.extend_from_slice(&pointer_offset.to_le_bytes());
            data.push(pointer_size);
            data.resize(data.len() + 7, 0); // Padding
        }
        LoaderCmd::AddChecksum {
            file,
            result_offset,
            start,
            length,
        } => {
            data.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
            append_fixed_string(data, file);
            data.extend_from_slice(&result_offset.to_le_bytes());
            data.extend_from_slice(&start.to_le_bytes());
            data.extend_from_slice(&length.to_le_bytes());
            data.resize(data.len() + 56, 0); // Padding
        }
    }
}

/// Searches for an ACPI table with the given signature and returns its offset,
/// checksum offset, and length.
fn find_acpi_table(tables: &[u8], signature: &str) -> Result<(u32, u32, u32)> {
    let sig_bytes = signature.as_bytes();
    if sig_bytes.len() != 4 {
        bail!("Signature must be 4 bytes long, but got '{signature}'");
    }

    let mut offset = 0;
    while offset < tables.len() {
        // Ensure there's enough space for a table header
        if offset + 8 > tables.len() {
            bail!("Table not found: {signature}");
        }

        let tbl_sig = &tables[offset..offset + 4];
        let tbl_len_bytes: [u8; 4] = tables[offset + 4..offset + 8].try_into().unwrap();
        let tbl_len = u32::from_le_bytes(tbl_len_bytes) as usize;

        if tbl_sig == sig_bytes {
            // Found the table
            return Ok((offset as u32, (offset + 9) as u32, tbl_len as u32));
        }

        if tbl_len == 0 {
            // Invalid table length, stop searching
            bail!("Found table with zero length at offset {offset}");
        }
        // Move to the next table
        offset += tbl_len;
    }

    bail!("Table not found: {signature}");
}
