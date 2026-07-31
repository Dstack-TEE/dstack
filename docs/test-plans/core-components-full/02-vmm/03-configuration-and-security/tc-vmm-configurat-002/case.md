<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-configurat-002"></a>
# TC-VMM-CONFIGURAT-002: External API authentication and listener separation

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-configurat-002](../../../feature-audit.md#req-vmm-configurat-002)
- Risks: [risk-vmm-configurat-002](../../../feature-audit.md#risk-vmm-configurat-002)
- Source: `dstack/vmm/src/main.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The fixture starts a case-owned authenticated VMM. Use `values.vmm.rpc_url`, the exact routes under `values.vmm.json_prpc_routes`, and the credential stored at `values.vmm.auth.token_file`. Read the token only into process memory; never print it, place it in argv, or persist it in evidence. The Host API remains independently available only through `values.host_api` over vsock.
- Establish the Step 1 healthy baseline with `Authorization: Bearer <token>` on
  every protected VMM HTTP/pRPC request. HTTP 401 without that header is the
  expected negative policy result, not evidence that the authenticated target
  is unhealthy. Record only the status code and response structure for valid,
  missing, and wrong credentials; never record request headers or token text.

## Objective

Verify external api authentication and listener separation across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-configurat-002-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for external api authentication and listener separation.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-configurat-002-step-02"></a>
### Step 2: Exercise the behavior

Call public VMM, host, UI, and log endpoints with valid, missing, expired, and wrong credentials.

**Expected results:**

- Only the intended surfaces are public; protected calls reject invalid credentials and host APIs remain bound to their private transport.

<a id="tc-vmm-configurat-002-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
