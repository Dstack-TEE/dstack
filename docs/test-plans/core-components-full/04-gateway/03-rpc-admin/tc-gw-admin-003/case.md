<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-admin-003"></a>
# TC-GW-ADMIN-003: Admin.Exit

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-admin-003](../../../feature-audit.md#req-gw-admin-003)
- Risks: [risk-gw-admin-003](../../../feature-audit.md#risk-gw-admin-003)
- Source: `dstack/gateway/rpc/proto/gateway_rpc.proto:381`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared RPC contract: `Admin.Exit` takes `google.protobuf.Empty` (no fields) and returns `google.protobuf.Empty` (no fields). The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../api-inventory.json); do not reconstruct it from implementation source.
- Empty-input transport semantics: exercise empty JSON/protobuf and extraneous JSON compatibility inputs. The current protobuf transport validates framing even for `google.protobuf.Empty`, so malformed protobuf must be rejected without invoking `Exit`; use an invalid pRPC route as a separate negative transport check. GET is an explicitly supported JSON transport and is not a negative case.
- For the candidate guest-agent target, use `automation/start-simulator.sh` and the recorded service socket/route, then `automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- Exercise the case-prescribed absent/default/valid/boundary-invalid/unknown-field and JSON/protobuf representations with a checked-in helper when available. Keep secret response material in memory and record only structural checks, public material, and hashes.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the complete request, response, authorization, state transition, and error contract of `Admin.Exit`.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `Admin.Exit` entry in [`api-inventory.json`](../../../api-inventory.json) is mandatory test data. `google.protobuf.Empty` has no request fields. Exercise the documented empty JSON/protobuf encodings plus extraneous JSON and malformed protobuf bytes. Confirm extraneous JSON compatibility and protobuf framing rejection, then validate every response field, nested message field, and presence bit. Use an invalid pRPC route for a separate negative routing check; GET is supported by `ra-rpc`.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-admin-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for admin.exit.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gw-admin-003-step-02"></a>
### Step 2: Exercise the behavior

Invoke `Admin.Exit` with a valid `google.protobuf.Empty` request using a valid admin credential on the dedicated admin listener; capture the binary and JSON pRPC representations. Then send extraneous JSON and malformed protobuf request bodies to confirm the current compatibility and framing semantics, exercise an invalid pRPC route, and, where protected, omit the credential.

**Expected results:**

- The valid call returns `google.protobuf.Empty` with every documented field and exhibits the documented `Exit` state and side effects; extraneous JSON is accepted, malformed protobuf is rejected without invoking `Exit`, invalid routing returns a structured transport error, and protected calls reject missing credentials.

<a id="tc-gw-admin-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with an invalid route or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid routing or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
