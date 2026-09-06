// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! GPU telemetry for the `GpuInfo` RPC.
//!
//! NVML is initialized once per process and reused. `Nvml`'s `Drop` shuts the
//! library down, so a request-scoped handle would init+shutdown on every
//! `/metrics` scrape. Init failure is retried after `INIT_FAILURE_TTL` so
//! images without a driver do not `dlopen` on every call, while a driver that
//! appears later can still be picked up.
//!
//! Sampling is serialized with `try_lock`. A stuck NVML call (GPU reset, driver
//! assert, CC handshake) keeps that one blocking thread and the sampler lock;
//! the RPC timeout does **not** cancel it. Later callers skip the lock and
//! return the last snapshot, or `error: "sampling in progress"` if none exists.
//! They never queue behind the hung sample.
//!
//! GpuInfo, `/metrics`, and the dashboard share one 5s snapshot so the three
//! entry points do not stampede NVML.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex, OnceLock, RwLock, TryLockError};
use std::time::{Duration, Instant};

use guest_api::{GpuDevice, GpuInfoResponse};
use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::{Device, Nvml};
use or_panic::ResultOrPanic;
use tracing::{debug, warn};

const SAMPLE_TTL: Duration = Duration::from_secs(5);
const INIT_FAILURE_TTL: Duration = Duration::from_secs(60);

struct GpuSampler {
    warned: HashSet<(u32, &'static str)>,
}

static NVML: OnceLock<Nvml> = OnceLock::new();
static SNAPSHOT: RwLock<Option<(Instant, GpuInfoResponse)>> = RwLock::new(None);
static SAMPLER: LazyLock<Mutex<GpuSampler>> = LazyLock::new(|| {
    Mutex::new(GpuSampler {
        warned: HashSet::new(),
    })
});

pub(crate) fn collect_gpu_info() -> GpuInfoResponse {
    if let Some(response) = fresh_snapshot() {
        return response;
    }

    let mut sampler = match SAMPLER.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => return snapshot_or_busy(),
        Err(TryLockError::Poisoned(_)) => SAMPLER.lock().or_panic("gpu sampler mutex poisoned"),
    };

    if let Some(response) = fresh_snapshot() {
        return response;
    }

    let response = sample(&mut sampler);
    *SNAPSHOT.write().or_panic("gpu snapshot lock poisoned") =
        Some((Instant::now(), response.clone()));
    response
}

fn fresh_snapshot() -> Option<GpuInfoResponse> {
    let snapshot = SNAPSHOT.read().or_panic("gpu snapshot lock poisoned");
    snapshot.as_ref().and_then(|(fetched_at, response)| {
        (fetched_at.elapsed() < ttl_for(response)).then(|| response.clone())
    })
}

fn snapshot_or_busy() -> GpuInfoResponse {
    let snapshot = SNAPSHOT.read().or_panic("gpu snapshot lock poisoned");
    if let Some((_, response)) = snapshot.as_ref() {
        return response.clone();
    }
    GpuInfoResponse {
        gpus: vec![],
        error: "sampling in progress".into(),
        cc_ready: None,
    }
}

fn ttl_for(response: &GpuInfoResponse) -> Duration {
    if response.error.is_empty() {
        SAMPLE_TTL
    } else {
        INIT_FAILURE_TTL
    }
}

fn sample(sampler: &mut GpuSampler) -> GpuInfoResponse {
    let nvml = match NVML.get() {
        Some(nvml) => nvml,
        None => match Nvml::init() {
            Ok(nvml) => {
                let _ = NVML.set(nvml);
                match NVML.get() {
                    Some(nvml) => nvml,
                    None => {
                        return GpuInfoResponse {
                            gpus: vec![],
                            error: "NVML handle missing after init".into(),
                            cc_ready: None,
                        };
                    }
                }
            }
            Err(e) => {
                let error = format!("failed to initialize NVML: {e}");
                warn!("{error}");
                return GpuInfoResponse {
                    gpus: vec![],
                    error,
                    cc_ready: None,
                };
            }
        },
    };

    let count = match nvml.device_count() {
        Ok(count) => count,
        Err(e) => {
            let error = format!("failed to get NVML GPU count: {e}");
            warn!("{error}");
            return GpuInfoResponse {
                gpus: vec![],
                error,
                cc_ready: None,
            };
        }
    };

    let cc_ready = query_cc_ready(sampler, nvml, count);
    GpuInfoResponse {
        gpus: (0..count)
            .map(|index| collect_device(sampler, nvml, index))
            .collect(),
        error: String::new(),
        cc_ready,
    }
}

fn query_cc_ready(sampler: &mut GpuSampler, nvml: &'static Nvml, count: u32) -> Option<bool> {
    if count == 0 {
        return None;
    }
    let device = match nvml.device_by_index(0) {
        Ok(device) => device,
        Err(e) => {
            log_query_error(sampler, 0, "cc_ready", &e);
            return None;
        }
    };
    match device.get_confidential_compute_state() {
        Ok(ready) => Some(ready),
        Err(e) => {
            log_query_error(sampler, 0, "cc_ready", &e);
            None
        }
    }
}

fn collect_device(sampler: &mut GpuSampler, nvml: &'static Nvml, index: u32) -> GpuDevice {
    match nvml.device_by_index(index) {
        Ok(device) => collect_device_fields(sampler, index, &device),
        Err(e) => {
            log_query_error(sampler, index, "device", &e);
            GpuDevice {
                index,
                error: format!("device: {e}"),
                ..Default::default()
            }
        }
    }
}

fn collect_device_fields(sampler: &mut GpuSampler, index: u32, device: &Device<'_>) -> GpuDevice {
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

    let cc_enabled = match device.is_cc_enabled() {
        Ok(enabled) => Some(enabled),
        Err(e) => {
            push_error(sampler, index, "cc_enabled", e, &mut errors);
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
        error: errors.join("; "),
        cc_enabled,
    }
}

fn push_error(
    sampler: &mut GpuSampler,
    index: u32,
    field: &'static str,
    err: NvmlError,
    errors: &mut Vec<String>,
) {
    errors.push(format!("{field}: {err}"));
    log_query_error(sampler, index, field, &err);
}

fn log_query_error(sampler: &mut GpuSampler, index: u32, field: &'static str, err: &NvmlError) {
    let first = sampler.warned.insert((index, field));
    if matches!(err, NvmlError::NotSupported) {
        debug!("GPU {index} {field} not supported: {err}");
    } else if first {
        warn!("failed to query GPU {index} {field}: {err}");
    } else {
        debug!("failed to query GPU {index} {field}: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::collect_gpu_info;

    /// NVML may or may not be present on the machine running this test.
    /// Unavailability must be an error with no devices, not a silent empty
    /// success (which would mean "NVML worked, zero GPUs"). A host with NVML
    /// just has to not panic.
    #[test]
    fn collect_reports_nvml_unavailability_without_panicking() {
        let info = collect_gpu_info();
        if info.error.is_empty() {
            return;
        }
        assert!(
            info.gpus.is_empty(),
            "NVML unavailability must not invent devices, got {:?}",
            info.gpus
        );
        assert_eq!(info.cc_ready, None);
    }
}
