// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use crate::QemuVersion;

/// Bus number of the expander in the single-node layout derived from
/// `hugepages` and `num_gpus`.
pub(crate) const LEGACY_PXB_BUS: u8 = 5;

/// Root-bus slot of the first node's `pxb-pcie`; node `i` takes slot `0x10 + i`.
pub(crate) const FIRST_PXB_SLOT: u8 = 0x10;

/// Slot of the ICH9 LPC bridge, the first one an expander cannot take.
const LPC_SLOT: u8 = 0x1f;

/// One guest NUMA node. vCPUs and RAM are split evenly across nodes, in node
/// order, as contiguous ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaNode {
    /// Bus number of the node's `pxb-pcie` expander (its `bus_nr`), if any.
    /// GPUs sit behind the expanders whenever there is one.
    pub pxb_bus: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineConfig {
    pub qemu_version: QemuVersion,
    pub cpu_count: u32,
    pub memory_size: u64,
    pub pic: bool,
    pub smm: bool,
    pub hugepages: bool,
    /// Guest NUMA nodes, in node-id order. Empty means the layout `hugepages`
    /// alone implies: one node, with an expander on bus 5 when GPUs are
    /// attached.
    pub numa_nodes: Vec<NumaNode>,
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
    #[error("the requested topology places {requested} devices before the fixed-address PXB, but QEMU has only {available} slots there")]
    TooManyPrePxbDevices { requested: u64, available: u64 },
    #[error("NVSwitch passthrough requires an iommufd object, but no GPU creates one")]
    NvswitchWithoutIommufd,
    #[error("PCI hotplug on root ports is not modeled; set hotplug_off for GPU passthrough")]
    HotplugWithRootPorts,
    #[error("NUMA nodes require hugepages")]
    NumaWithoutHugepages,
    #[error("{what} ({count}) must split evenly across {nodes} NUMA nodes")]
    UnevenNumaSplit {
        what: &'static str,
        count: u64,
        nodes: usize,
    },
    #[error("{0} PXB expanders do not fit on the root bus")]
    TooManyPxbs(usize),
    #[error("PXB bus numbers must be nonzero and distinct: {0:?}")]
    InvalidPxbBuses(Vec<u8>),
}

impl MachineConfig {
    /// The guest NUMA nodes, explicit or implied by `hugepages`.
    pub(crate) fn numa_layout(&self) -> Cow<'_, [NumaNode]> {
        if !self.numa_nodes.is_empty() || !self.hugepages {
            return Cow::Borrowed(&self.numa_nodes);
        }
        Cow::Owned(vec![NumaNode {
            pxb_bus: (self.num_gpus > 0).then_some(LEGACY_PXB_BUS),
        }])
    }

    /// The expanders' bus numbers, in node order.
    pub(crate) fn pxb_buses(&self) -> Vec<u8> {
        self.numa_layout()
            .iter()
            .filter_map(|n| n.pxb_bus)
            .collect()
    }

    fn validate_numa(&self) -> Result<(), TopologyError> {
        let nodes = self.numa_nodes.len();
        if nodes == 0 {
            return Ok(());
        }
        if !self.hugepages {
            return Err(TopologyError::NumaWithoutHugepages);
        }
        for (what, count) in [
            ("cpu_count", u64::from(self.cpu_count)),
            ("memory_size", self.memory_size),
        ] {
            if count % nodes as u64 != 0 {
                return Err(TopologyError::UnevenNumaSplit { what, count, nodes });
            }
        }
        let buses = self.pxb_buses();
        if buses.len() > usize::from(LPC_SLOT - FIRST_PXB_SLOT) {
            return Err(TopologyError::TooManyPxbs(buses.len()));
        }
        let mut sorted = buses.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != buses.len() || sorted.first() == Some(&0) {
            return Err(TopologyError::InvalidPxbBuses(buses));
        }
        Ok(())
    }

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
        self.validate_numa()?;
        let pxbs = self.pxb_buses().len();
        if pxbs == 1 && self.num_gpus > 32 {
            return Err(TopologyError::TooManyPxbPorts {
                requested: self.num_gpus,
            });
        }
        if pxbs > 0 {
            let requested = 4
                + u64::from(self.root_verity)
                + u64::from(self.num_nics)
                + u64::from(self.num_verity_volumes);
            if requested > 16 {
                return Err(TopologyError::TooManyPrePxbDevices {
                    requested,
                    available: 16,
                });
            }
        }
        let fixed_delta = i64::from(self.root_verity) - 1;
        let passthrough_ports = if pxbs > 0 {
            i64::from(self.num_nvswitches)
        } else {
            i64::from(self.num_gpus) + i64::from(self.num_nvswitches)
        };
        let requested = i64::from(self.num_nics)
            + i64::from(self.num_verity_volumes)
            + fixed_delta
            + passthrough_ports;
        let available = 26 - pxbs as i64;
        if requested > available {
            return Err(TopologyError::TooManyRootBusDevices {
                requested,
                available,
            });
        }
        if self.num_nvswitches > 0 && self.num_gpus == 0 {
            return Err(TopologyError::NvswitchWithoutIommufd);
        }
        if !self.hotplug_off && passthrough_ports > 0 {
            return Err(TopologyError::HotplugWithRootPorts);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pxb_config() -> MachineConfig {
        MachineConfig {
            qemu_version: QemuVersion::new(11, 1, 0),
            cpu_count: 1,
            memory_size: 2 << 30,
            pic: false,
            smm: false,
            hugepages: true,
            numa_nodes: vec![],
            num_gpus: 1,
            num_nvswitches: 0,
            num_nics: 1,
            num_verity_volumes: 0,
            hotplug_off: false,
            root_verity: true,
            pci_hole64_size: None,
        }
    }

    #[test]
    fn fixed_address_pxb_slot_must_remain_free() {
        let mut config = pxb_config();
        config.num_nics = 11;
        assert!(config.validate().is_ok());

        config.num_nics = 12;
        assert!(matches!(
            config.validate(),
            Err(TopologyError::TooManyPrePxbDevices {
                requested: 17,
                available: 16
            })
        ));
    }

    #[test]
    fn root_port_passthrough_requires_hotplug_off() {
        let mut config = pxb_config();
        config.hugepages = false;
        assert!(matches!(
            config.validate(),
            Err(TopologyError::HotplugWithRootPorts)
        ));

        config.hotplug_off = true;
        assert!(config.validate().is_ok());
    }
}
