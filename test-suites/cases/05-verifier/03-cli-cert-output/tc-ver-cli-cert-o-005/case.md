<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-cli-cert-o-005"></a>
# TC-INT-CLI-CERT-O-005: Configuration validation and trust roots

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-ver-cli-cert-o-005](../../../../catalog/feature-audit.md#req-ver-cli-cert-o-005)
- Risks: [risk-ver-cli-cert-o-005](../../../../catalog/feature-audit.md#risk-ver-cli-cert-o-005)
- Source: `dstack/verifier/src/main.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Exercise the prepared candidate binary directly. Do not probe raw-substrate service ports or block because they are not listening; this section tests offline CLI/certificate behavior.

## Objective

Verify configuration validation and trust roots across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The prepared candidate verifier binary and checked-in non-production fixtures are available.
2. Commands use isolated test data and preserve native request and response output. These one-shot CLI and certificate checks do not require a network listener; ports in a raw-substrate fixture are allocations, not running services.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-ver-cli-cert-o-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for configuration validation and trust roots.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-ver-cli-cert-o-005-step-02"></a>
### Step 2: Exercise the behavior

Load custom/default trust roots, image sources, PCCS/collateral, timeouts, proxies, and conflicting settings.

**Expected results:**

- Valid config controls only intended verifier behavior; missing/invalid roots and unsafe conflicts fail at startup.

<a id="tc-ver-cli-cert-o-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
