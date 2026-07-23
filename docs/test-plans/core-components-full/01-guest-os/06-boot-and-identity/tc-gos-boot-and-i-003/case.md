<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-boot-and-i-003"></a>
# TC-GOS-BOOT-AND-I-003: System and user configuration materialization

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-boot-and-i-003](../../../feature-audit.md#req-gos-boot-and-i-003)
- Risks: [risk-gos-boot-and-i-003](../../../feature-audit.md#risk-gos-boot-and-i-003)
- Source: `os/common/rootfs/dstack-prepare.sh`

## Objective

Verify system and user configuration materialization across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-boot-and-i-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for system and user configuration materialization.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-boot-and-i-003-step-02"></a>
### Step 2: Exercise the behavior

Provide sys-config, user-config, compose, encrypted environment, and optional simulator config.

**Expected results:**

- Each file is copied to its documented location with restrictive ownership; missing optional files do not corrupt required state.

<a id="tc-gos-boot-and-i-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
