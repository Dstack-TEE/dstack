<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-026"></a>
# TC-GOS-SETUP-026: GPU telemetry collector CLI output contract

## Metadata

- Priority: P1
- Type: Functional, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-setup-026](../../../../catalog/feature-audit.md#req-gos-setup-026)
- Risks: [risk-gos-setup-026](../../../../catalog/feature-audit.md#risk-gos-setup-026)
- Source: `dstack/dstack-util/src/gpu_info.rs`, `dstack/dstack-util/src/main.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use `prepared_binaries.dstack_util` as the binary under test. Do not rebuild it.
- `dstack-util gpu-info` is the one-shot NVML sampler the guest agent spawns for `GuestApi.GpuInfo`, `/metrics`, and the dashboard. Its protocol is: exit 0 whenever a result can be produced (including "NVML unavailable"), exactly one JSON `GpuInfoResponse` object on stdout, and all logs on stderr.
- Documented shapes: a non-empty `error` means NVML or the device count was unavailable, and then `gpus` is empty and both CC fields are `null`; empty `error` with empty `gpus` means no NVIDIA GPU; a sample lists devices in NVML index order with optional scalars (`null` when that query failed) and one `errors` string per failed query. The collector never sets `sample_age_ms`; that belongs to the agent cache.
- The case runs the prepared binary on the fixture host. Whether the host has NVML or NVIDIA display devices only selects which documented shape is valid; GPU-positive sampling inside a CVM is owned by the hardware-gated [tc-gos-platform-009](../../10-platform-services/tc-gos-platform-009/case.md#tc-gos-platform-009).

## Objective

Verify that `dstack-util gpu-info` emits exactly one documented `GpuInfoResponse` JSON document on stdout with exit status 0, keeps logs off stdout, and leaves no process behind.

## Preconditions

1. The prepared `dstack-util` binary exists and is executable.
2. The host NVIDIA display-class PCI device count is read from `/sys/bus/pci/devices` (vendor `0x10de`, class `0x0300`/`0x0302`) before the command runs.

## Test Data

```json
{
  "argv": ["gpu-info"],
  "verbose_environment": {"RUST_LOG": "trace"},
  "invalid_argv": ["gpu-info", "--unexpected"],
  "top_level_fields": ["gpus", "error", "cc_ready", "cc_enabled", "sample_age_ms"]
}
```

## Steps

<a id="tc-gos-setup-026-step-01"></a>
### Step 1: Sample once with default logging

Run `dstack-util gpu-info` with stdin closed and classify the stdout document.

**Expected results:**

- Exit status is 0; stdout is exactly one newline-terminated line that parses as a JSON object with exactly the five top-level fields.
- `sample_age_ms` is `null`, and the document matches one documented shape; a host with zero NVIDIA display devices never yields a sampled shape.
- An unavailable result is accompanied by a `WARN` line on stderr.

<a id="tc-gos-setup-026-step-02"></a>
### Step 2: Keep diagnostics off stdout and reject invalid arguments

Repeat with `RUST_LOG=trace`, then run with an unknown argument.

**Expected results:**

- The trace-level run still writes exactly one JSON line on stdout; when the first result was not a sample, the document is identical to Step 1.
- The unknown argument exits non-zero and writes nothing to stdout.

<a id="tc-gos-setup-026-step-03"></a>
### Step 3: Verify one-shot process lifetime

Run the command again and look for any new process whose executable is the prepared binary.

**Expected results:**

- The repeated run satisfies Step 1 and no `dstack-util` collector process remains after it exits.

## Postconditions

No state is created. Preserve the CLI matrix artifact; no NVML error text is stored beyond its SHA-256 digest.
