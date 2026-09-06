// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! GPU telemetry collection isolated in a helper process.
//!
//! NVML calls cannot be cancelled safely. Keeping them in a child process lets
//! the agent terminate and recreate the sampler after a driver call hangs. The
//! helper keeps one NVML handle for its lifetime. Successful samples are cached
//! for five seconds; initialization failures are cached for one minute.

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::process::Stdio;
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use guest_api::{GpuDevice, GpuInfoResponse};
use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::{Device, Nvml};
use or_panic::ResultOrPanic;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, warn};

const SAMPLE_TTL: Duration = Duration::from_secs(5);
const INIT_FAILURE_TTL: Duration = Duration::from_secs(60);
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(4);

struct GpuSampler {
    warned: HashSet<(u32, &'static str)>,
}

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

static SNAPSHOT: RwLock<Option<(Instant, GpuInfoResponse)>> = RwLock::new(None);
static WORKER: LazyLock<Mutex<Option<Worker>>> = LazyLock::new(|| Mutex::new(None));

/// Returns a fresh sample, starting or restarting the isolated NVML worker as needed.
pub(crate) async fn collect_gpu_info() -> GpuInfoResponse {
    if let Some(response) = fresh_snapshot() {
        return response;
    }

    let mut worker_slot = match WORKER.try_lock() {
        Ok(guard) => guard,
        Err(_) => return unavailable("GPU sampling is in progress"),
    };

    if let Some(response) = fresh_snapshot() {
        return response;
    }

    let result = timeout(SAMPLE_TIMEOUT, sample_worker(&mut worker_slot)).await;
    let response = match result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            stop_worker(&mut worker_slot);
            unavailable(format!("GPU sampler failed: {error:#}"))
        }
        Err(_) => {
            stop_worker(&mut worker_slot);
            unavailable("GPU sampling timed out")
        }
    };
    *SNAPSHOT.write().or_panic("gpu snapshot lock poisoned") =
        Some((Instant::now(), response.clone()));
    response
}

/// Returns immediately for Prometheus. An expired cache starts a refresh in the
/// background so a wedged GPU cannot delay unrelated guest metrics.
pub(crate) fn collect_gpu_info_nonblocking() -> GpuInfoResponse {
    if let Some(response) = fresh_snapshot() {
        return response;
    }
    tokio::spawn(async {
        let _ = collect_gpu_info().await;
    });
    unavailable("GPU sample is not available yet")
}

fn fresh_snapshot() -> Option<GpuInfoResponse> {
    let snapshot = SNAPSHOT.read().or_panic("gpu snapshot lock poisoned");
    snapshot.as_ref().and_then(|(fetched_at, response)| {
        (fetched_at.elapsed() < ttl_for(response)).then(|| response.clone())
    })
}

fn ttl_for(response: &GpuInfoResponse) -> Duration {
    if response.error.is_empty() {
        SAMPLE_TTL
    } else {
        INIT_FAILURE_TTL
    }
}

fn unavailable(error: impl Into<String>) -> GpuInfoResponse {
    GpuInfoResponse {
        gpus: vec![],
        error: error.into(),
        cc_ready: None,
    }
}

async fn sample_worker(slot: &mut Option<Worker>) -> Result<GpuInfoResponse> {
    if slot.is_none() {
        *slot = Some(start_worker()?);
    }
    let worker = slot.as_mut().context("GPU sampler worker is missing")?;
    worker.stdin.write_all(b"sample\n").await?;
    worker.stdin.flush().await?;
    let mut line = String::new();
    let bytes = worker.stdout.read_line(&mut line).await?;
    if bytes == 0 {
        let status = worker.child.wait().await?;
        return Err(anyhow!("GPU sampler exited with {status}"));
    }
    serde_json::from_str(&line).context("invalid response from GPU sampler")
}

fn start_worker() -> Result<Worker> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--gpu-info-helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start GPU sampler")?;
    let stdin = child.stdin.take().context("GPU sampler stdin is missing")?;
    let stdout = child
        .stdout
        .take()
        .context("GPU sampler stdout is missing")?;
    Ok(Worker {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

fn stop_worker(slot: &mut Option<Worker>) {
    if let Some(mut worker) = slot.take() {
        let _ = worker.child.start_kill();
        tokio::spawn(async move {
            let _ = worker.child.wait().await;
        });
    }
}

/// Entry point for the hidden helper mode. Each request is one line on stdin
/// and each response is one JSON line on stdout.
pub fn run_gpu_info_helper() -> Result<()> {
    let nvml = Nvml::init().map_err(|error| format!("failed to initialize NVML: {error}"));
    let mut sampler = GpuSampler {
        warned: HashSet::new(),
    };
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        if line? != "sample" {
            continue;
        }
        let response = match &nvml {
            Ok(nvml) => sample(&mut sampler, nvml),
            Err(error) => unavailable(error),
        };
        serde_json::to_writer(&mut stdout, &response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

fn sample(sampler: &mut GpuSampler, nvml: &Nvml) -> GpuInfoResponse {
    let count = match nvml.device_count() {
        Ok(count) => count,
        Err(e) => {
            let error = format!("failed to get NVML GPU count: {e}");
            warn!("{error}");
            return unavailable(error);
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

fn query_cc_ready(sampler: &mut GpuSampler, nvml: &Nvml, count: u32) -> Option<bool> {
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

fn collect_device(sampler: &mut GpuSampler, nvml: &Nvml, index: u32) -> GpuDevice {
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
    use super::{sample, unavailable, GpuSampler};
    use nvml_wrapper::Nvml;
    use std::collections::HashSet;

    /// NVML may or may not be present on the machine running this test.
    /// Unavailability must be an error with no devices, not a silent empty
    /// success (which would mean "NVML worked, zero GPUs").
    #[test]
    fn collect_reports_nvml_unavailability_without_panicking() {
        let info = match Nvml::init() {
            Ok(nvml) => sample(
                &mut GpuSampler {
                    warned: HashSet::new(),
                },
                &nvml,
            ),
            Err(error) => unavailable(format!("failed to initialize NVML: {error}")),
        };
        if info.error.is_empty() {
            return;
        }
        assert!(info.gpus.is_empty());
        assert_eq!(info.cc_ready, None);
    }
}
