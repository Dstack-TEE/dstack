// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! GPU telemetry, sampled out of process and cached.
//!
//! Three properties drive the shape of this module:
//!
//! 1. **A guest without an NVIDIA card pays nothing.** PCI topology is fixed
//!    for a CVM's lifetime -- the VMM assigns GPUs through VFIO when QEMU
//!    starts and never hot-plugs -- so the scan runs once and every later
//!    request is an atomic load returning a constant.
//! 2. **NVML never runs in this process.** `dstack-util gpu-info` samples in a
//!    short-lived child that can be killed when a driver call wedges. Nothing
//!    stays resident between samples, and each sample re-initializes NVML, so a
//!    driver that loads late is picked up instead of being cached as "no GPU".
//! 3. **Stale beats nothing.** Callers get the last known snapshot with its age
//!    attached and a refresh is kicked off behind them. Returning a placeholder
//!    on expiry would mean a Prometheus scrape slower than the TTL -- which is
//!    every realistic scrape interval -- never sees a single GPU series.

use std::path::Path;
use std::process::Stdio;
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use cached_cell::TtlCell;
use guest_api::GpuInfoResponse;
#[cfg(test)]
use or_panic::ResultOrPanic;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, warn};

/// How long a snapshot is served before a refresh is triggered. Older snapshots
/// are still served, just with a refresh started behind them.
const SAMPLE_TTL: Duration = Duration::from_secs(5);
/// Upper bound on one `dstack-util gpu-info` run. Generous because a cold
/// `nvmlInit_v2` on a multi-GPU CC system is not fast, but finite because the
/// whole point of the child process is that a wedged driver can be abandoned.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(10);

/// The collector, installed into the rootfs alongside this agent.
const DSTACK_UTIL: &str = "/usr/bin/dstack-util";
/// Set by tests to point at a stub collector.
#[cfg(test)]
static COLLECTOR_OVERRIDE: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

static SNAPSHOT: LazyLock<TtlCell<GpuInfoResponse>> = LazyLock::new(|| TtlCell::new(SAMPLE_TTL));
/// Serializes refreshes so a burst of scrapes spawns one collector, not N.
static REFRESH_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Why this guest cannot produce GPU telemetry, if it cannot.
enum Gate {
    /// No NVIDIA device on the PCI bus. Nothing to report, ever.
    NoGpu,
    /// A card is present but the kernel module is not loaded yet.
    NoDriver,
    /// Sampling is worth attempting.
    Sample,
}

fn gate() -> Gate {
    if !nvidia_on_pci() {
        return Gate::NoGpu;
    }
    // Unlike PCI presence this is not fixed: the module can load after the
    // agent starts, so it is re-checked every time. It is one `stat`.
    if !Path::new("/sys/module/nvidia").exists() {
        return Gate::NoDriver;
    }
    Gate::Sample
}

/// True when an NVIDIA display device is attached to the PCI bus.
///
/// Cached for the process lifetime. A CVM's GPUs are fixed at launch by the
/// VMM's VFIO assignment; there is no hot-plug path that could change this
/// answer, and paying a directory scan on every scrape of every GPU-less guest
/// is exactly the cost this gate exists to avoid.
///
/// Fails open to "no GPU" where the boot attestation gate in `dstack-util`
/// fails closed on the same inventory: refusing to report telemetry is the
/// safe direction here, and spawning a collector forever on a guest whose
/// sysfs cannot be read is not.
fn nvidia_on_pci() -> bool {
    static PRESENT: OnceLock<bool> = OnceLock::new();
    *PRESENT.get_or_init(|| match lspci::sysfs::gpu_inventory() {
        Ok(inventory) => inventory.has_nvidia(),
        Err(error) => {
            warn!("failed to scan PCI for GPUs, assuming none: {error:#}");
            false
        }
    })
}

/// Returns the best answer available without ever blocking.
///
/// Serves the last snapshot whatever its age, annotated with `sample_age_ms`,
/// and starts a refresh behind the caller when that snapshot has aged past the
/// TTL. Used by `/metrics` and the dashboard, where a wedged GPU must not
/// delay unrelated guest data. Only the very first call on a GPU guest returns
/// "not sampled yet".
pub(crate) fn gpu_info() -> GpuInfoResponse {
    match gate() {
        Gate::NoGpu => return no_gpus(),
        Gate::NoDriver => return unavailable("NVIDIA driver is not loaded"),
        Gate::Sample => {}
    }

    let cached = SNAPSHOT.get_allow_stale().ok();
    let needs_refresh = cached
        .as_ref()
        .is_none_or(|snapshot| snapshot.age() >= SAMPLE_TTL);
    if needs_refresh {
        tokio::spawn(refresh_if_free());
    }
    serve(cached)
}

/// Like [`gpu_info`], but waits for a first sample when the cache is cold.
///
/// The `GpuInfo` RPC is a direct question from an operator or the control
/// plane, so "ask again in five seconds" is a worse answer than a bounded
/// wait. The wait is bounded twice: by [`SAMPLE_TIMEOUT`] here and by the RPC
/// timeout at the call site.
pub(crate) async fn gpu_info_awaited() -> GpuInfoResponse {
    match gate() {
        Gate::NoGpu => return no_gpus(),
        Gate::NoDriver => return unavailable("NVIDIA driver is not loaded"),
        Gate::Sample => {}
    }

    if SNAPSHOT.get_allow_stale().is_err() {
        // Cold cache. Queue behind any in-flight sample rather than reporting
        // nothing; whoever wins the lock fills the cache for both.
        let _guard = REFRESH_LOCK.lock().await;
        if SNAPSHOT.get_allow_stale().is_err() {
            sample_into_cache().await;
        }
    }
    gpu_info()
}

fn serve(cached: Option<cached_cell::Snapshot<GpuInfoResponse>>) -> GpuInfoResponse {
    match cached {
        Some(snapshot) => {
            let mut response = snapshot.value().clone();
            response.sample_age_ms = Some(snapshot.age().as_millis() as u64);
            response
        }
        None => unavailable("GPU sample is not available yet"),
    }
}

/// Runs one collection unless another one is already in flight.
///
/// Dropping the refresh when the lock is held is deliberate: a burst of scrapes
/// must spawn one collector, not one per scrape, and the waiting callers are
/// already being served the previous snapshot.
async fn refresh_if_free() {
    let Ok(_guard) = REFRESH_LOCK.try_lock() else {
        debug!("GPU sample already in progress, skipping refresh");
        return;
    };
    // Another task may have refreshed between the staleness check and here.
    if SNAPSHOT.get().is_ok() {
        return;
    }
    sample_into_cache().await;
}

/// Collects once and stores the outcome, success or failure.
///
/// Failures are cached like successes so a guest whose driver is broken reports
/// the reason instead of an empty device list, and so a hard-failing collector
/// is not re-spawned on every single scrape.
///
/// Caller must hold [`REFRESH_LOCK`].
async fn sample_into_cache() {
    match timeout(SAMPLE_TIMEOUT, collect()).await {
        Ok(Ok(response)) => {
            SNAPSHOT.set(response);
        }
        Ok(Err(error)) => {
            warn!("failed to sample GPU telemetry: {error:#}");
            SNAPSHOT.set(unavailable(format!("GPU sampling failed: {error:#}")));
        }
        Err(_) => {
            warn!("GPU sampling timed out after {SAMPLE_TIMEOUT:?}");
            SNAPSHOT.set(unavailable("GPU sampling timed out"));
        }
    }
}

/// Spawns `dstack-util gpu-info` and parses its stdout.
///
/// `kill_on_drop` matters: the timeout above drops this future, and a wedged
/// NVML call inside the child must not outlive it.
async fn collect() -> Result<GpuInfoResponse> {
    let collector = collector_path();
    if !Path::new(&collector).exists() {
        bail!("{collector} is not installed");
    }
    let output = Command::new(&collector)
        .arg("gpu-info")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("failed to run {collector} gpu-info"))?;
    // The collector logs to stderr and reserves stdout for the document, so
    // anything here is diagnostics worth keeping rather than protocol noise.
    if !output.stderr.is_empty() {
        warn!(
            "gpu-info collector: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if !output.status.success() {
        bail!("gpu-info collector exited with {}", output.status);
    }
    serde_json::from_slice(&output.stdout).context("invalid gpu-info output")
}

fn collector_path() -> String {
    #[cfg(test)]
    if let Some(path) = COLLECTOR_OVERRIDE
        .read()
        .or_panic("collector override poisoned")
        .clone()
    {
        return path;
    }
    DSTACK_UTIL.to_string()
}

/// The guest has no NVIDIA hardware. Empty devices with no error is the
/// documented encoding for "the collector ran and found nothing".
fn no_gpus() -> GpuInfoResponse {
    GpuInfoResponse::default()
}

fn unavailable(error: impl Into<String>) -> GpuInfoResponse {
    GpuInfoResponse {
        error: error.into(),
        ..Default::default()
    }
}

/// Test-only hooks. Production callers go through [`gpu_info`].
#[cfg(test)]
mod test_support {
    use super::*;

    pub(super) fn set_snapshot(response: GpuInfoResponse) {
        SNAPSHOT.set(response);
    }

    pub(super) fn hold_refresh_lock() -> tokio::sync::MutexGuard<'static, ()> {
        REFRESH_LOCK.try_lock().expect("refresh lock is free")
    }

    pub(super) fn set_collector(path: &str) {
        *COLLECTOR_OVERRIDE
            .write()
            .or_panic("collector override poisoned") = Some(path.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guest_api::GpuDevice;
    use std::os::unix::fs::PermissionsExt;

    fn sample_response() -> GpuInfoResponse {
        GpuInfoResponse {
            gpus: vec![GpuDevice {
                index: 0,
                uuid: "GPU-abc".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// A guest with no NVIDIA device must not scan, spawn, or cache anything.
    /// The distinction that matters downstream is "no GPUs" (empty, no error)
    /// versus "could not tell" (error set).
    #[test]
    fn a_guest_without_a_card_reports_no_gpus_rather_than_an_error() {
        let response = no_gpus();
        assert!(response.gpus.is_empty());
        assert!(response.error.is_empty());
        assert_eq!(response.sample_age_ms, None);
    }

    /// The bug this design exists to prevent: a scrape interval longer than the
    /// TTL must still see the GPU series. Serving a placeholder on expiry meant
    /// `/metrics` reported zero GPUs forever at Prometheus' default 15s.
    #[tokio::test]
    async fn a_snapshot_older_than_the_ttl_is_still_served() {
        // Hold the refresh lock so the spawned refresh cannot overwrite the
        // snapshot mid-assertion on a machine that does have a GPU.
        let _guard = test_support::hold_refresh_lock();
        test_support::set_snapshot(sample_response());

        let served = serve(SNAPSHOT.get_allow_stale().ok());

        assert!(
            served.error.is_empty(),
            "stale data must not become an error"
        );
        assert_eq!(served.gpus.len(), 1);
        assert!(served.sample_age_ms.is_some(), "age must be reported");
    }

    /// The reason sampling lives in a child process: when a driver call wedges,
    /// the timeout must actually reclaim it. Nothing may be left running
    /// between samples.
    #[tokio::test]
    async fn a_collector_that_hangs_is_killed_when_the_sample_times_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("stub-collector");
        let pid_file = dir.path().join("pid");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho $$ > {}\nsleep 60\n", pid_file.display()),
        )
        .expect("write stub");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub");

        let _guard = test_support::hold_refresh_lock();
        test_support::set_collector(&script.to_string_lossy());

        let outcome = timeout(Duration::from_millis(500), collect()).await;
        assert!(outcome.is_err(), "the stub sleeps far past the timeout");

        let pid: i32 = std::fs::read_to_string(&pid_file)
            .expect("stub recorded its pid")
            .trim()
            .parse()
            .expect("pid is a number");

        // SIGKILL is asynchronous; give the kernel a moment to reap.
        for _ in 0..50 {
            if !Path::new(&format!("/proc/{pid}")).exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("collector {pid} survived the sample timeout");
    }

    /// A collector that is not installed must degrade to a recorded error, not
    /// a panic and not a silent "no GPUs".
    #[tokio::test]
    async fn a_missing_collector_is_reported_as_an_error() {
        test_support::set_collector("/nonexistent/dstack-util");
        let error = collect().await.expect_err("must fail");
        assert!(
            error.to_string().contains("not installed"),
            "unexpected error: {error:#}"
        );
    }
}
