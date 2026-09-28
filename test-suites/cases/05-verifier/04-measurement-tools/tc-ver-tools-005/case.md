<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-tools-005"></a>
# TC-VER-TOOLS-005: Collateral and trust-root update lifecycle

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-ver-tools-005](../../../../catalog/feature-audit.md#req-ver-tools-005)
- Risks: [risk-ver-tools-005](../../../../catalog/feature-audit.md#risk-ver-tools-005)
- Source: `dstack/verifier/src/verification.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The verifier has no live collateral or trust-root update API. Roots and
  collateral URLs are loaded when the process constructs its attestation
  verifier. The supported update lifecycle is an atomic case-owned config
  replacement followed by a bounded process restart. Do not fail because a
  live-update endpoint, generation API, or zero-downtime reload is absent.

## Objective

Verify collateral and trust-root update lifecycle with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-ver-tools-005-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-ver-tools-005-step-02"></a>
### Step 2: Exercise supported and boundary paths

Using non-production fixtures, atomically replace Intel/AMD/cloud/TPM root or
collateral configuration, restart the case-owned verifier, and verify the new
configuration. Restore the previous configuration and restart again. Submit
concurrent requests before each restart to prove that a running process never
observes a partially written configuration.

**Expected results:**

- Each process instance uses exactly one complete configuration; accepted
  fixture roots take effect after restart, invalid or untrusted roots fail
  closed at startup or verification, and restoring the previous complete
  configuration recovers the original behavior. A bounded restart interval is
  expected and is not a live-reload failure.

<a id="tc-ver-tools-005-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Invalid configuration or an interrupted restart is bounded, fails closed,
  produces actionable redacted diagnostics, leaves no partially written
  trusted configuration, and the valid atomic configuration plus restart
  recovers service.

<a id="tc-ver-tools-005-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- The selected complete configuration persists across a case-owned restart,
  transient process state disappears, adjacent identities are unchanged, and
  no private key, credential, or plaintext sentinel appears in APIs, metrics,
  dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
