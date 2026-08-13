// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::QemuVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineConfig {
    pub qemu_version: QemuVersion,
    pub cpu_count: u32,
    pub memory_size: u64,
    pub pic: bool,
    pub smm: bool,
    pub hugepages: bool,
    pub num_gpus: u32,
    pub num_nvswitches: u32,
    pub num_nics: u32,
    pub num_verity_volumes: u32,
    pub hotplug_off: bool,
    pub root_verity: bool,
    pub pci_hole64_size: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum TopologyError {
    #[error("cpu_count must be greater than zero")]
    NoCpus,
    #[error("memory_size must be greater than zero")]
    NoMemory,
    #[error("cpu_count exceeds the Q35 limit of 4096: {0}")]
    TooManyCpus(u32),
    #[error("the requested topology needs {requested} devices on the root PCIe bus, but QEMU has only {available} free slots")]
    TooManyRootBusDevices { requested: i64, available: i64 },
    #[error("the requested topology needs {requested} GPU root ports on the PXB, but QEMU supports at most 32")]
    TooManyPxbPorts { requested: u32 },
    #[error("NVSwitch passthrough requires an iommufd object, but no GPU creates one")]
    NvswitchWithoutIommufd,
}

impl MachineConfig {
    pub fn validate(&self) -> Result<(), TopologyError> {
        if self.cpu_count == 0 {
            return Err(TopologyError::NoCpus);
        }
        if self.memory_size == 0 {
            return Err(TopologyError::NoMemory);
        }
        if self.cpu_count > 4096 {
            return Err(TopologyError::TooManyCpus(self.cpu_count));
        }
        if self.hugepages && self.num_gpus > 32 {
            return Err(TopologyError::TooManyPxbPorts {
                requested: self.num_gpus,
            });
        }
        let fixed_delta = i64::from(self.root_verity) - 1;
        let passthrough_ports = if self.hugepages && self.num_gpus > 0 {
            i64::from(self.num_nvswitches)
        } else {
            i64::from(self.num_gpus) + i64::from(self.num_nvswitches)
        };
        let requested = i64::from(self.num_nics)
            + i64::from(self.num_verity_volumes)
            + fixed_delta
            + passthrough_ports;
        let available = if self.hugepages && self.num_gpus > 0 {
            25
        } else {
            26
        };
        if requested > available {
            return Err(TopologyError::TooManyRootBusDevices {
                requested,
                available,
            });
        }
        if self.num_nvswitches > 0 && self.num_gpus == 0 {
            return Err(TopologyError::NvswitchWithoutIommufd);
        }
        Ok(())
    }
}
