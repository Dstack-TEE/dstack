// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! One-shot NVML sampler behind `dstack-util gpu-info`.
//!
//! NVML calls cannot be cancelled: a driver that wedges during a GPU reset or a
//! CC handshake blocks the calling thread until it decides to return. Running
//! the sample in a short-lived process lets `dstack-guest-agent` kill it and
//! move on, and keeps `libnvidia-ml` out of the long-lived agent entirely.
//!
//! One process per sample also means `Nvml::init()` runs fresh every time, so a
//! driver that loads after the agent started is picked up on the next sample
//! instead of being cached as "no GPU" for the agent's lifetime.
//!
//! This command owns collection only. Caching, presence gating and timeouts
//! belong to the caller.

use std::collections::HashSet;

use anyhow::Result;
use guest_api::{GpuDevice, GpuInfoResponse};
use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::{Device, Nvml};
use tracing::{debug, warn};

/// Per-run state for error log deduplication.
///
/// A single run touches each (device, field) pair once, so this only collapses
/// the repeats that a multi-GPU box would otherwise produce for the same
/// unsupported counter on every card.
#[derive(Default)]
struct Sampler {
    warned: HashSet<(u32, &'static str)>,
}

/// Samples every NVIDIA GPU visible to NVML and prints the result as one JSON
/// object on stdout.
///
/// Exits zero even when NVML is unavailable: "no driver" is a result the caller
/// needs to record, not a failure of this command. A non-zero exit is reserved
/// for not being able to produce a result at all.
pub fn cmd_gpu_info() -> Result<()> {
    let response = collect();
    serde_json::to_writer(std::io::stdout(), &response)?;
    println!();
    Ok(())
}

fn collect() -> GpuInfoResponse {
    let nvml = match Nvml::init() {
        Ok(nvml) => nvml,
        Err(err) => {
            // Expected on any guest without an NVIDIA driver. The caller gates
            // on PCI presence, so reaching here means a card is attached but
            // the library is missing -- worth a warning.
            warn!("failed to initialize NVML: {err}");
            return unavailable(format!("failed to initialize NVML: {err}"));
        }
    };
    sample(&mut Sampler::default(), &nvml)
}

fn unavailable(error: impl Into<String>) -> GpuInfoResponse {
    GpuInfoResponse {
        gpus: vec![],
        error: error.into(),
        cc_ready: None,
        cc_enabled: None,
        sample_age_ms: None,
    }
}

fn sample(sampler: &mut Sampler, nvml: &Nvml) -> GpuInfoResponse {
    let count = match nvml.device_count() {
        Ok(count) => count,
        Err(e) => {
            let error = format!("failed to get NVML GPU count: {e}");
            warn!("{error}");
            return unavailable(error);
        }
    };

    // Both CC queries are system-wide despite hanging off `Device`, so ask once
    // through device 0 rather than once per card.
    let (cc_ready, cc_enabled) = query_cc_state(sampler, nvml, count);
    GpuInfoResponse {
        gpus: (0..count)
            .map(|index| collect_device(sampler, nvml, index))
            .collect(),
        error: String::new(),
        cc_ready,
        cc_enabled,
        sample_age_ms: None,
    }
}

/// Reads the system-wide confidential-computing state.
///
/// `get_confidential_compute_state` is `nvmlSystemGetConfComputeGpusReadyState`
/// and `is_cc_enabled` is `nvmlSystemGetConfComputeSettings`; neither uses the
/// device handle it is called on. Any device will do, so device 0 is used.
fn query_cc_state(sampler: &mut Sampler, nvml: &Nvml, count: u32) -> (Option<bool>, Option<bool>) {
    if count == 0 {
        return (None, None);
    }
    let device = match nvml.device_by_index(0) {
        Ok(device) => device,
        Err(e) => {
            log_query_error(sampler, 0, "cc_state", &e);
            return (None, None);
        }
    };
    let ready = match device.get_confidential_compute_state() {
        Ok(ready) => Some(ready),
        Err(e) => {
            log_query_error(sampler, 0, "cc_ready", &e);
            None
        }
    };
    let enabled = match device.is_cc_enabled() {
        Ok(enabled) => Some(enabled),
        Err(e) => {
            log_query_error(sampler, 0, "cc_enabled", &e);
            None
        }
    };
    (ready, enabled)
}

fn collect_device(sampler: &mut Sampler, nvml: &Nvml, index: u32) -> GpuDevice {
    match nvml.device_by_index(index) {
        Ok(device) => collect_device_fields(sampler, index, &device),
        Err(e) => {
            log_query_error(sampler, index, "device", &e);
            GpuDevice {
                index,
                errors: vec![format!("device: {e}")],
                ..Default::default()
            }
        }
    }
}

fn collect_device_fields(sampler: &mut Sampler, index: u32, device: &Device<'_>) -> GpuDevice {
    let mut errors = Vec::new();

    let uuid = match device.uuid() {
        Ok(uuid) => uuid,
        Err(e) => {
            push_error(sampler, index, "uuid", e, &mut errors);
            String::new()
        }
    };
    let pci_bus_id = match device.pci_info() {
        Ok(pci) => pci.bus_id,
        Err(e) => {
            push_error(sampler, index, "pci_bus_id", e, &mut errors);
            String::new()
        }
    };

    let (utilization_gpu, utilization_memory) = match device.utilization_rates() {
        Ok(util) => (Some(util.gpu), Some(util.memory)),
        Err(e) => {
            push_error(sampler, index, "utilization", e, &mut errors);
            (None, None)
        }
    };

    let (memory_total_bytes, memory_used_bytes, memory_free_bytes) = match device.memory_info() {
        Ok(mem) => (Some(mem.total), Some(mem.used), Some(mem.free)),
        Err(e) => {
            push_error(sampler, index, "memory", e, &mut errors);
            (None, None, None)
        }
    };

    let temperature_c = match device.temperature(TemperatureSensor::Gpu) {
        Ok(temp) => Some(temp),
        Err(e) => {
            push_error(sampler, index, "temperature", e, &mut errors);
            None
        }
    };

    let power_usage_mw = match device.power_usage() {
        Ok(power) => Some(power),
        Err(e) => {
            push_error(sampler, index, "power", e, &mut errors);
            None
        }
    };

    GpuDevice {
        index,
        uuid,
        pci_bus_id,
        utilization_gpu,
        utilization_memory,
        memory_total_bytes,
        memory_used_bytes,
        memory_free_bytes,
        temperature_c,
        power_usage_mw,
        errors,
    }
}

fn push_error(
    sampler: &mut Sampler,
    index: u32,
    field: &'static str,
    err: NvmlError,
    errors: &mut Vec<String>,
) {
    errors.push(format!("{field}: {err}"));
    log_query_error(sampler, index, field, &err);
}

fn log_query_error(sampler: &mut Sampler, index: u32, field: &'static str, err: &NvmlError) {
    let first = sampler.warned.insert((index, field));
    if matches!(err, NvmlError::NotSupported) {
        // CC mode disables some counters by design; that is not an incident.
        debug!("GPU {index} {field} not supported: {err}");
    } else if first {
        warn!("failed to query GPU {index} {field}: {err}");
    } else {
        debug!("failed to query GPU {index} {field}: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NVML may or may not be present on the machine running this test.
    /// Unavailability must be an error with no devices, not a silent empty
    /// success (which would mean "NVML worked, zero GPUs").
    #[test]
    fn collect_reports_nvml_unavailability_without_panicking() {
        let info = collect();
        if info.error.is_empty() {
            return;
        }
        assert!(info.gpus.is_empty());
        assert_eq!(info.cc_ready, None);
        assert_eq!(info.cc_enabled, None);
    }

    /// The guest agent parses stdout as one JSON object. A response must
    /// survive that round trip with `None` distinct from `Some(0)`.
    #[test]
    fn response_round_trips_through_json() {
        let original = GpuInfoResponse {
            gpus: vec![GpuDevice {
                index: 0,
                uuid: "GPU-abc".into(),
                pci_bus_id: "00000000:01:00.0".into(),
                utilization_gpu: Some(0),
                utilization_memory: None,
                memory_total_bytes: Some(8 << 30),
                memory_used_bytes: Some(0),
                memory_free_bytes: None,
                temperature_c: Some(40),
                power_usage_mw: None,
                errors: vec!["power: not supported".into()],
            }],
            error: String::new(),
            cc_ready: Some(true),
            cc_enabled: Some(true),
            sample_age_ms: None,
        };
        let encoded = serde_json::to_string(&original).expect("encode");
        assert!(!encoded.contains('\n'), "one JSON line per sample");
        let decoded: GpuInfoResponse = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.gpus[0].utilization_gpu, Some(0));
        assert_eq!(decoded.gpus[0].utilization_memory, None);
    }
}
