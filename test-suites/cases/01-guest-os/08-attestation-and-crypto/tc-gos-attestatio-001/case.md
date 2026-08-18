<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-attestatio-001"></a>
# TC-GOS-ATTESTATIO-001: Quote report-data binding and hash algorithms

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-attestatio-001](../../../../catalog/feature-audit.md#req-gos-attestatio-001)
- Risks: [risk-gos-attestatio-001](../../../../catalog/feature-audit.md#risk-gos-attestatio-001)
- Source: `dstack/guest-agent/src/rpc_service.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify quote report-data binding and hash algorithms across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-attestatio-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for quote report-data binding and hash algorithms.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-attestatio-001-step-02"></a>
### Step 2: Exercise the behavior

Request quotes with every documented hash, prefix, raw 64-byte data, boundary lengths, and unknown algorithms.

**Expected results:**

- Report data matches the documented prefix/hash transform; raw length is enforced and unsupported algorithms are rejected.

<a id="tc-gos-attestatio-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
