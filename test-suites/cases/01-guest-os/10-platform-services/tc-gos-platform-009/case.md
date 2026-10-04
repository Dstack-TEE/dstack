<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-platform-009"></a>
# TC-GOS-PLATFORM-009: NVIDIA device initialization and attestation failure

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-platform-009](../../../../catalog/feature-audit.md#req-gos-platform-009)
- Risks: [risk-gos-platform-009](../../../../catalog/feature-audit.md#risk-gos-platform-009)
- Source: `os/yocto/layers/meta-nvidia`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify nvidia device initialization and attestation failure with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-gos-platform-009-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-gos-platform-009-step-02"></a>
### Step 2: Exercise supported and boundary paths

Boot supported GPU assignment, missing driver/device, altered attestation output, and partial multi-GPU failure.

**Expected results:**

- Only assigned devices appear, driver and evidence match inventory, and failed attestation is explicit without exposing device to an untrusted workload.

<a id="tc-gos-platform-009-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-gos-platform-009-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Post-baseline regression coverage (GPU telemetry series, commits 7ef6c27e88 through 477c2eab64)

This coverage is hardware-gated with the rest of the case: without an attachable NVIDIA GPU the capability probe finalizes BLOCKED. The CPU-only shapes are covered by [tc-gos-guestapi-006](../../04-rpc-guestapi/tc-gos-guestapi-006/case.md#tc-gos-guestapi-006) and [tc-gos-observabil-001](../../09-observability-and-network/tc-gos-observabil-001/case.md#tc-gos-observabil-001).

- With the driver loaded, `GuestApi.GpuInfo` returns one `GpuDevice` per assigned card with a non-empty `uuid`, the NVML `pci_bus_id` of that card, populated scalars or one `errors` entry per failed query (never a zero standing in for a failed query), system-wide `cc_enabled`/`cc_ready` matching `nvidia-smi conf-compute` output, and `sample_age_ms`.
- The first call on a cold cache waits for a sample; later calls return within the RPC timeout while the served sample ages, and `/metrics` exposes the same cards as `dstack_gpu_*` series with the full UUID and PCI labels, `dstack_gpu_nvml_up 1`, and `dstack_gpu_sample_age_seconds`.
- With the card present but the `nvidia` module not loaded, `GpuInfo` returns `error` `NVIDIA driver is not loaded`, no devices, and unset CC fields; `/metrics` reports `dstack_gpu_nvml_up 0`.
- A `dstack-util gpu-info` collector that hangs is killed at the sample timeout, leaves no process behind, and the next sample is not attempted until the failure backoff elapses; the agent keeps serving `/metrics` for CPU, memory, and disk during the hang.
- `dstack-util gpu-info` run by hand inside the CVM prints exactly one JSON document on stdout, with NVML warnings on stderr only.

## Post-baseline regression coverage (PR #1156, #1157, #1173, #1177, #1181, #1191)

This coverage is hardware-gated with the rest of the case. The static image content behind it (command line, driver pin, linker cache, library resolution, blacklist, and the GPU-less module-option result) is mandatory in [tc-gos-platform-005](../tc-gos-platform-005/case.md#tc-gos-platform-005-step-05).

- PR #1156: with MMCONFIG enabled, `lspci -vvv` on each assigned GPU shows extended capabilities (offset `>= 0x100`, including the NVIDIA vendor DVSEC on Blackwell), the `nvidia` probe logs no extended-config-space assertion, and a CUDA `cuInit()` inside a GPU container returns success rather than `CUDA_ERROR_SYSTEM_NOT_READY` (802).
- PR #1157: `/run/modprobe.d/nvidia-dstack.conf` records the assigned topology before `systemd-udev-trigger.service` starts. A single-GPU guest carries exactly `options nvidia NVreg_NvLinkDisable=1`; a Hopper Protected PCIe guest with NVSwitches carries exactly `NVreg_RegistryDwords="RmEnableProtectedPcie=0x1"`; a Blackwell multi-GPU guest carries neither. `/sys/module/nvidia/parameters` reflects the generated option, and `journalctl -b` shows `nvidia-module-options.service` finished before the first `nvidia` module load, which came from `nvidia-persistenced.service` or `nvidia-fabricmanager.service` rather than udev.
- PR #1177: `nvidia-smi` and `/proc/driver/nvidia/version` report driver `595.91.07`, matching the loaded module and the guest firmware directory.
- PR #1173: `nvattest` runs during `dstack-prepare.service` without a shared-library load error, so a GPU CVM completes boot.
- PR #1181 and #1191: a GPU container started through the NVIDIA container runtime hook sees its device and does not fail at `libnvidia-container-go.so.1` dlopen.
- PR #1192 and #1194: a sustained host-to-device and device-to-host transfer burst (for example repeated pinned and pageable `cudaMemcpy` of at least 1 GiB per GPU for five minutes) grows SWIOTLB beyond its boot pool without a `swiotlb buffer is full` error, and `journalctl -k -b` contains no `scheduling while atomic`, `swiotlb_dyn_free`, `set_memory_encrypted` warning, or kernel panic; the guest remains running afterwards.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
