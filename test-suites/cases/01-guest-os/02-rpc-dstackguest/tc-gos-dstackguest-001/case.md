<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-dstackguest-001"></a>
# TC-GOS-DSTACKGUEST-001: DstackGuest.GetTlsKey

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-dstackguest-001](../../../../catalog/feature-audit.md#req-gos-dstackguest-001)
- Risks: [risk-gos-dstackguest-001](../../../../catalog/feature-audit.md#risk-gos-dstackguest-001)
- Source: `dstack/guest-agent/rpc/proto/agent_rpc.proto:41`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared RPC contract: `DstackGuest.GetTlsKey` takes `GetTlsKeyArgs` (`subject: string`, `alt_names: string`, `usage_ra_tls: bool`, `usage_server_auth: bool`, `usage_client_auth: bool`, `not_before: uint64`, `not_after: uint64`, `with_app_info: bool`) and returns `GetTlsKeyResponse` (`key: string`, `certificate_chain: string`). The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../../catalog/api-inventory.json); do not reconstruct it from implementation source.
- For the candidate guest-agent target, use `shared/automation/start-simulator.sh` and the recorded service socket/route, then `shared/automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- Exercise the case-prescribed absent/default/valid/boundary-invalid/unknown-field and JSON/protobuf representations with a checked-in helper when available. Keep secret response material in memory and record only structural checks, public material, and hashes.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the complete request, response, authorization, state transition, and error contract of `DstackGuest.GetTlsKey`.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `DstackGuest.GetTlsKey` entry in [`api-inventory.json`](../../../../catalog/api-inventory.json) is mandatory test data. Exercise every request field and every recursively referenced message field as absent/default, valid, boundary-invalid and combined with an unknown field; validate every response field, nested message field, and presence bit.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-dstackguest-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for dstackguest.gettlskey.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-dstackguest-001-step-02"></a>
### Step 2: Exercise the behavior

Invoke `DstackGuest.GetTlsKey` with a valid `GetTlsKeyArgs` request using valid service-specific authentication and attestation context; capture the binary and JSON pRPC representations. Then send a schema-invalid request and, where protected, omit the credential.

**Expected results:**

- The valid call returns `GetTlsKeyResponse` with every documented field and exhibits the documented `GetTlsKey` state and side effects; invalid framing or fields return a structured error, and protected calls reject missing credentials.

<a id="tc-gos-dstackguest-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PRs #1116, #1118, #1122, and #1124)

- Exercise both frozen v0 and v1 guest-agent routes in the same candidate image and prove that v0 method names and wire fields remain unchanged.
- For v1, validate byte-valued request and response fields without UTF-8 coercion, structured pRPC status codes, missing-field defaults, malformed protobuf, and unknown fields.
- Confirm v0 compatibility aliases do not appear in the v1 schema and v1-only routes are not silently served through v0.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
