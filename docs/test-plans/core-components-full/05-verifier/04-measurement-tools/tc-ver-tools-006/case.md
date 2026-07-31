<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-tools-006"></a>
# TC-VER-TOOLS-006: Verifier denial-of-service input limits

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-ver-tools-006](../../../feature-audit.md#req-ver-tools-006)
- Risks: [risk-ver-tools-006](../../../feature-audit.md#risk-ver-tools-006)
- Source: `dstack/verifier/src/main.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Use the checked-in `tdx-lite-attestation.json` or
  `sev-snp-attestation.json` as the post-stress valid control. Do not use the
  full-TDX fixture as the availability control when the case-owned verifier's
  image-download URL intentionally has no backing image server; that tests a
  different dependency rather than verifier availability.
- Do not replace the provider-owned verifier process merely to satisfy Step 4:
  its cleanup handle records the original PID. For this stateless DoS case,
  repeated health and valid verification on the original process prove
  persistence and recovery unless a restart interface is explicitly present
  in the case manifest.

## Objective

Verify verifier denial-of-service input limits with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-ver-tools-006-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-ver-tools-006-step-02"></a>
### Step 2: Exercise supported and boundary paths

Submit deeply nested, oversized, compressed, event-heavy, certificate-chain-heavy, and slow image/evidence inputs concurrently.

**Expected results:**

- Configured size/time/concurrency limits bound CPU, memory, disk, and network while health and later valid verification remain available.

<a id="tc-ver-tools-006-step-03"></a>
### Step 3: Exercise failure and recovery

Inject malformed/oversized input and interrupt a case-owned dependency only
when the case manifest provides a restorable dependency. Restore any injected
dependency fault and repeat the fixture-backed valid control.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics,
  leaves no partial trusted state, and the fixture-backed valid control
  succeeds after recovery. A dependency that was absent in the baseline is not
  an injectable interruption and need not be invented.

<a id="tc-ver-tools-006-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
