<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-boot-and-i-001"></a>
# TC-GOS-BOOT-AND-I-001: Measured boot and prepare ordering

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-boot-and-i-001](../../../feature-audit.md#req-gos-boot-and-i-001)
- Risks: [risk-gos-boot-and-i-001](../../../feature-audit.md#risk-gos-boot-and-i-001)
- Source: `os/common/rootfs/dstack-prepare.service`

## Objective

Verify measured boot and prepare ordering across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-boot-and-i-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for measured boot and prepare ordering.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-boot-and-i-001-step-02"></a>
### Step 2: Exercise the behavior

Boot through systemd preparation and app-compose startup.

**Expected results:**

- Preparation completes once before Docker/app startup; identity, measurements, and configuration files exist before consumers start.

<a id="tc-gos-boot-and-i-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
