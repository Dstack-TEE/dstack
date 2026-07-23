<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-internal-002"></a>
# TC-GW-INTERNAL-002: Gateway debug key generation artifact safety

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gw-internal-002](../../../feature-audit.md#req-gw-internal-002)
- Risks: [risk-gw-internal-002](../../../feature-audit.md#risk-gw-internal-002)
- Source: `dstack/gateway/src/gen_debug_key.rs`

## Objective

Verify gateway debug key generation artifact safety exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use an isolated deployment with the relevant effective configuration and a clean run-scoped baseline.
2. Enable redacted process, file, RPC, and lifecycle evidence collection.

## Test Data

Include minimum, maximum, duplicate, missing, malformed, and cross-instance values appropriate to the behavior.

## Steps

<a id="tc-gw-internal-002-step-01"></a>
### Step 1: Record effective inputs and baseline

Capture effective configuration, input files/requests, existing processes/resources, and public status before the operation.

**Expected results:**

- Inputs resolve unambiguously to the intended test identity and no run-scoped output or resource exists.

<a id="tc-gw-internal-002-step-02"></a>
### Step 2: Exercise behavior and boundaries

Generate debug key data twice with target existing, unsafe permissions/path, interrupted write and production-config consumption attempt.

**Expected results:**

- Output is atomic, restricted, explicitly debug-labeled, not silently overwritten, and production startup refuses it.

<a id="tc-gw-internal-002-step-03"></a>
### Step 3: Inject failure and concurrency

Interrupt the primary dependency at its commit boundary, issue a conflicting concurrent operation, restore it, and retry once.

**Expected results:**

- At most one operation commits, failure cleanup releases all temporary resources, diagnostics identify the failed phase, and retry converges without duplicate state.

<a id="tc-gw-internal-002-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Restart the owning service where permitted and inspect state for this and an adjacent identity plus all collected output.

**Expected results:**

- Persisted and transient state follow policy, adjacent identities are unchanged, and no private material or credential appears in output.

## Postconditions

Remove run-scoped state and verify processes, files, devices, listeners, and allocations match baseline.
