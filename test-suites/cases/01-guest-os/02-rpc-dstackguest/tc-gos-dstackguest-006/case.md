<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-dstackguest-006"></a>
# TC-GOS-DSTACKGUEST-006: Removed legacy DstackGuest.GpuInfo route

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-dstackguest-006](../../../../catalog/feature-audit.md#req-gos-dstackguest-006)
- Risks: [risk-gos-dstackguest-006](../../../../catalog/feature-audit.md#risk-gos-dstackguest-006)
- Source: `dstack/guest-agent/rpc/proto/agent_rpc.proto:57`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared compatibility contract: the never-shipped v0 `GpuInfo` method is absent and GPU attestation is owned by `dstack.guest.v1.AttestGpu` on `/v1`. The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../../catalog/api-inventory.json); do not reconstruct it from implementation source.
- Empty-input transport semantics: `prpc-build` intentionally generates a zero-argument handler for `google.protobuf.Empty` and does not decode the request body. Exercise empty and extraneous/malformed bodies as body-ignored compatibility inputs, and use an invalid pRPC route for the negative transport check; GET is an explicitly supported JSON transport and is not a negative case. Do not expect malformed body rejection from an Empty-input handler.
- For the candidate guest-agent target, use `shared/automation/start-simulator.sh` and the recorded service socket/route, then `shared/automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- Exercise the case-prescribed absent/default/valid/boundary-invalid/unknown-field and JSON/protobuf representations with a checked-in helper when available. Keep secret response material in memory and record only structural checks, public material, and hashes.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify that the never-shipped legacy `GpuInfo` route remains absent and is not reintroduced as an alias for the v1 GPU API.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Probe `GpuInfo` on every DstackGuest mount of the internal socket (the fixture route, `/v0`, `/prpc`, and `/v1`) using JSON and protobuf framing, probe `/v1/AttestGpu` with a deliberately invalid nonce, and call `GuestApi.GpuInfo` once on the guest API listener. The DstackGuest routes must be absent, the v1 attestation method must be routed and return a capability or validation status rather than 404, and the GuestApi method must return the telemetry schema.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-dstackguest-006-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for dstackguest.gpuinfo.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-dstackguest-006-step-02"></a>
### Step 2: Exercise the behavior

Probe the removed route on each DstackGuest mount with JSON and protobuf framing, then probe the v1 replacement route with an invalid nonce, then call the separate `GuestApi.GpuInfo` telemetry method.

**Expected results:**

- Every DstackGuest `GpuInfo` probe returns HTTP 404 with a diagnostic, while `/v1/AttestGpu` is routed and returns its documented validation or capability error.
- `GuestApi.GpuInfo` on the guest API listener returns HTTP 200 with a `gpus` array and no `attestation` field.

<a id="tc-gos-dstackguest-006-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with an invalid route or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid routing or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (GPU telemetry series, commits a2dd3c89c8 and 85cc6bef92)

- `GpuInfo` is now a method name again, but on `GuestApi` (telemetry, `guest_api.proto`) rather than on `DstackGuest` (attestation). This case keeps asserting the DstackGuest removal on the unversioned, `/v0`, `/prpc`, and `/v1` mounts, and additionally proves the telemetry method is served only by the guest API listener with the telemetry schema. The telemetry contract itself is owned by [tc-gos-guestapi-006](../../04-rpc-guestapi/tc-gos-guestapi-006/case.md#tc-gos-guestapi-006).

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
