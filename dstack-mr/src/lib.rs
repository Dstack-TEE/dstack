// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

pub use machine::{Machine, TdxMeasurementDetails};

use util::{measure_log, measure_sha384, utf16_encode};

pub type RtmrLog = Vec<Vec<u8>>;
pub type RtmrLogs = [RtmrLog; 3];

mod acpi;
mod kernel;
mod machine;
mod num;
mod tdvf;
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
