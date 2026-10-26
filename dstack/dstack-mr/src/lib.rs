// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

pub use dstack_types::OvmfVariant;
pub use machine::{Machine, TdxMeasurementDetails};

use util::{measure_log, measure_sha384, utf16_encode};

pub type RtmrLog = Vec<Vec<u8>>;
pub type RtmrLogs = [RtmrLog; 3];

mod acpi;
mod kernel;
mod machine;
pub mod measurement;
mod num;
pub mod sev;
mod tdvf;
pub mod tdx;
mod util;

/// Contains all the measurement values for TDX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxMeasurements {
    #[serde(with = "hex_bytes")]
    pub mrtd: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr0: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr1: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr2: Vec<u8>,
}
