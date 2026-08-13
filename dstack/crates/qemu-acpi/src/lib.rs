// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pure Rust generation of the QEMU Q35 ACPI blobs measured by dstack.
//!
//! This crate intentionally models the observable ACPI ABI rather than a
//! virtual machine. Its output is expected to match QEMU byte for byte for a
//! supported compatibility profile and machine topology.
//!
//! QEMU releases newer than the newest modeled profile are generated with that
//! profile (see [`QemuVersion::compatibility`]) instead of being rejected, so a
//! QEMU upgrade that leaves the ACPI ABI alone keeps working and one that does
//! not surfaces as a blob mismatch the caller can act on.

mod aml_patch;
mod cpu;
mod fw_cfg;
mod profile;
mod srat;
mod tables;
mod topology;

pub use profile::{Compatibility, QemuVersion};
pub use topology::{MachineConfig, TopologyError};

/// Allocation granularity of QEMU's `etc/acpi/tables` fw_cfg blob.
pub const TABLE_BLOB_SIZE: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpiBlobs {
    pub tables: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub loader: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Topology(#[from] TopologyError),
    #[error("no ACPI compatibility profile for QEMU {0}; releases older than 8.0 are not modeled")]
    UnsupportedVersion(QemuVersion),
    #[error("malformed generated ACPI tables: missing {0}")]
    MalformedTables(String),
}

/// Generate the complete set of fw_cfg blobs measured by dstack.
///
/// The implementation accepts arbitrary valid counts and sizes; the familiar
/// small matrices used by differential tests are not implementation limits.
pub fn build(config: &MachineConfig) -> Result<AcpiBlobs, Error> {
    config.validate()?;
    tables::build(config)
}
