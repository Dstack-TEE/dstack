<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-ui-observa-002"></a>
# TC-VMM-UI-OBSERVA-002: Console log channels follow and ANSI handling

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-ui-observa-002](../../../../catalog/feature-audit.md#req-vmm-ui-observa-002)
- Risks: [risk-vmm-ui-observa-002](../../../../catalog/feature-audit.md#risk-vmm-ui-observa-002)
- Source: `dstack/vmm/src/main_routes.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify console log channels follow and ansi handling across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials. Historical and live markers must be written only through the case-owned controller to immediately registered VM work directories.

## Interface semantics

- `serial`, `stdout`, and `stderr` are the only valid channels; an unknown channel returns HTTP 400.
- The VM identifier must resolve through the in-memory VMM inventory before any log path is derived; unknown and traversal-shaped identifiers return HTTP 404.
- `ansi=false` strips terminal escape sequences while `ansi=true` preserves them.
- A follow response begins with the requested historical tail and continues at the same file position, without duplicating or dropping a boundary line.

## Steps

<a id="tc-vmm-ui-observa-002-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for console log channels follow and ansi handling.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-ui-observa-002-step-02"></a>
### Step 2: Exercise the behavior

Read stdout/stderr/serial logs with lines/follow/ANSI and invalid VM/channel.

**Expected results:**

- Historical tail and live continuation have no gap/duplication; ANSI policy works and cross-VM/path access is rejected.

<a id="tc-vmm-ui-observa-002-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
