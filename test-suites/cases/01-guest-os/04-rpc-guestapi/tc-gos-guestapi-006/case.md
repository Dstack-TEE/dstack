<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-guestapi-006"></a>
# TC-GOS-GUESTAPI-006: GuestApi.GpuInfo

## Metadata

- Priority: P1
- Type: Functional, API, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-guestapi-006](../../../../catalog/feature-audit.md#req-gos-guestapi-006)
- Risks: [risk-gos-guestapi-006](../../../../catalog/feature-audit.md#risk-gos-guestapi-006)
- Source: `dstack/guest-api/proto/guest_api.proto:195`, `dstack/guest-agent/src/gpu_info.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared RPC contract: `GuestApi.GpuInfo` takes `google.protobuf.Empty` (no fields) and returns `GpuInfoResponse` (`gpus: repeated GpuDevice`, `error: string`, `cc_ready: optional bool`, `cc_enabled: optional bool`, `sample_age_ms: optional uint64`). `GpuDevice` carries `index`, `uuid`, `pci_bus_id`, optional utilization/memory/temperature/power scalars, and `repeated string errors`. The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../../catalog/api-inventory.json); do not reconstruct it from implementation source.
- Documented response shapes: empty `gpus` with empty `error` means the guest has no NVIDIA GPU; a non-empty `error` means NVML or the sample was unavailable, and then `gpus` is empty and both CC fields are unset; a sample carries `sample_age_ms`. `cc_ready` and `cc_enabled` are system-wide, not per device.
- The guest agent gates sampling on an NVIDIA display-class device on the PCI bus (`/sys/bus/pci/devices`, vendor `0x10de`, class `0x0300`/`0x0302`). The simulator reads the host bus, so a host without such a device must return the no-GPU shape and must not spawn a collector.
- Empty-input transport semantics: `prpc-build` intentionally generates a zero-argument handler for `google.protobuf.Empty` and does not decode the request body. Use an invalid pRPC route for the negative transport check; GET is an explicitly supported JSON transport and is not a negative case.
- For the candidate guest-agent target, use `shared/automation/start-simulator.sh` and the recorded `GuestApi` service socket/route, then `shared/automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- GPU-positive telemetry (real devices, CC state, per-field query errors, stale-sample serving) needs attached NVIDIA hardware and is owned by the hardware-gated [tc-gos-platform-009](../../10-platform-services/tc-gos-platform-009/case.md#tc-gos-platform-009); this case does not report it.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify that `GuestApi.GpuInfo` returns the documented telemetry response shape over JSON and protobuf, distinguishes "no GPU" from "unavailable", and rejects invalid routing.

## Preconditions

1. The shared plan prerequisites are healthy and the guest API listener is reachable.
2. The host NVIDIA display-device count is read from sysfs before the call, so the expected shape is decided independently of the response.

## Test Data

The `GuestApi.GpuInfo` entry in [`api-inventory.json`](../../../../catalog/api-inventory.json) is mandatory test data. `google.protobuf.Empty` has no request fields.

```json
{
  "no_gpu_expected_json": {"gpus": [], "error": "", "cc_ready": null, "cc_enabled": null, "sample_age_ms": null},
  "no_gpu_expected_protobuf_bytes": 0
}
```

## Steps

<a id="tc-gos-guestapi-006-step-01"></a>
### Step 1: Inspect the effective prerequisite

Confirm the lease-owned simulator `GuestApi` socket exists, load the indexed contract, and count host NVIDIA display-class PCI devices.

**Expected results:**

- The socket is a Unix socket, exactly one inventory entry exists for `GuestApi.GpuInfo`, and the device count is recorded.

<a id="tc-gos-guestapi-006-step-02"></a>
### Step 2: Exercise the behavior

Invoke `GuestApi.GpuInfo` with an empty JSON body and an empty protobuf body, then call an invalid route.

**Expected results:**

- Both valid calls return HTTP 200 and the JSON response contains every indexed field, with the three optional fields present as `null` when unset.
- With zero NVIDIA display devices, the JSON response equals the no-GPU test data exactly, the protobuf response is zero bytes, and a repeated call is byte-identical.
- With an NVIDIA display device present, the response is either unavailable (non-empty `error`, empty `gpus`, both CC fields `null`) or a sample carrying `sample_age_ms`.
- The invalid route returns HTTP 4xx with a JSON `error` string.

<a id="tc-gos-guestapi-006-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Repeat the valid JSON request after the invalid-route probe.

**Expected results:**

- The repeated request returns HTTP 200; no response body is persisted beyond structural fields and hashes.

## Postconditions

Stop the lease-owned simulator. Preserve the regression matrix in the result artifacts.
