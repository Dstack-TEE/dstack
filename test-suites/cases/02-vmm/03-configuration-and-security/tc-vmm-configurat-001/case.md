<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-configurat-001"></a>
# TC-VMM-CONFIGURAT-001: Configuration defaults and validation

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-vmm-configurat-001](../../../../catalog/feature-audit.md#req-vmm-configurat-001)
- Risks: [risk-vmm-configurat-001](../../../../catalog/feature-audit.md#risk-vmm-configurat-001)
- Source: `dstack/vmm/src/config.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- The shipped example can omit Rocket's top-level management `port`, while the current `check-config` command requires both management endpoint fields. Detect that omission and add run-scoped `port = 0` only to generated matrix copies before invoking `check-config`; retain whether preparation was required in bounded evidence and never edit the shipped file.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify configuration defaults and validation across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `vmm` portion of [`configuration-inventory.json`](../../../../catalog/configuration-inventory.json) is mandatory test data. Exercise every listed field at its implicit default, an explicit valid value, boundary-invalid values, an unknown sibling field, and after restart.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-configurat-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for configuration defaults and validation.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-configurat-001-step-02"></a>
### Step 2: Exercise the behavior

Load minimal, full, unknown, conflicting, and invalid vmm.toml settings.

**Expected results:**

- Defaults are documented and stable; invalid platform, networking, key-provider, GPU, listener, and path combinations fail before serving.

<a id="tc-vmm-configurat-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
