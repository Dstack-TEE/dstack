<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-startup-001"></a>
# TC-KMS-STARTUP-001: Onboard, main, admin, metrics, and health listener startup

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-startup-001](../../../feature-audit.md#req-kms-startup-001)
- Risks: [risk-kms-startup-001](../../../feature-audit.md#risk-kms-startup-001)
- Source: `dstack/kms/src/main.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify KMS starts only the listeners allowed by its initialized/onboarding state and transitions atomically to the main service.

## Preconditions

1. Prepare separate fresh-uninitialized, partially initialized, fully initialized, and corrupted-state directories.
2. Reserve and monitor all configured public, onboard, admin, metrics, and health addresses.

## Test Data

The `kms` portion of [`configuration-inventory.json`](../../../configuration-inventory.json) is mandatory test data. Exercise every listed field at its implicit default, an explicit valid value, boundary-invalid values, an unknown sibling field, and after restart.

Use valid/minimal/full configuration plus bind conflicts, missing TLS files, invalid admin configuration, and an interrupted Finish transition.

## Steps

<a id="tc-kms-startup-001-step-01"></a>
### Step 1: Start an uninitialized KMS

Start against fresh state and probe every configured listener and representative RPC.

**Expected results:**

- Only the onboarding and intended health surfaces are available; app-key, key-handover, signing, and admin operations cannot be reached before initialization.

<a id="tc-kms-startup-001-step-02"></a>
### Step 2: Complete onboarding and transition

Bootstrap or onboard with valid evidence, call Finish, and continuously probe listener availability through the transition.

**Expected results:**

- State commits once, onboarding closes, main/admin/metrics listeners open with correct authentication, and there is no interval exposing both unrestricted onboarding and initialized key service.

<a id="tc-kms-startup-001-step-03"></a>
### Step 3: Exercise startup failures and restart

Repeat with each bind/TLS/config/state failure, interrupt Finish, then restart from fully committed and partial state.

**Expected results:**

- Startup failure is explicit and releases all binds; committed state restarts in main mode with the same CA/root; partial/corrupt state fails closed and never generates a replacement root.

<a id="tc-kms-startup-001-step-04"></a>
### Step 4: Verify listener isolation and redaction

Call each method on every wrong listener with missing/wrong credentials and inspect logs, metrics, and process arguments.

**Expected results:**

- Methods are available only on their intended listener, auth is consistent, and no root key, temporary CA key, token, or onboarding secret appears in observability output.

## Postconditions

Remove test state and confirm all listeners and processes have stopped.
