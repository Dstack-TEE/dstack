<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-entry-001"></a>
# TC-GOS-ENTRY-001: Guest-agent configuration precedence and compose deserialization

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-entry-001](../../../feature-audit.md#req-gos-entry-001)
- Risks: [risk-gos-entry-001](../../../feature-audit.md#risk-gos-entry-001)
- Source: `dstack/guest-agent/src/config.rs`

## Objective

Verify guest-agent configuration precedence and compose deserialization exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use an isolated deployment with the relevant effective configuration and a clean run-scoped baseline.
2. Enable redacted process, file, RPC, and lifecycle evidence collection.

## Test Data

The `guest-agent` portion of [`configuration-inventory.json`](../../../configuration-inventory.json) is mandatory test data. Exercise every listed field at its implicit default, an explicit valid value, boundary-invalid values, an unknown sibling field, and after restart.

Include minimum, maximum, duplicate, missing, malformed, and cross-instance values appropriate to the behavior.

## Steps

<a id="tc-gos-entry-001-step-01"></a>
### Step 1: Record effective inputs and baseline

Capture effective configuration, input files/requests, existing processes/resources, and public status before the operation.

**Expected results:**

- Inputs resolve unambiguously to the intended test identity and no run-scoped output or resource exists.

<a id="tc-gos-entry-001-step-02"></a>
### Step 2: Exercise behavior and boundaries

Load embedded defaults, explicit file, environment overrides, Unix/TCP/vsock binds, valid compose, unknown fields, malformed compose, and absent optional values.

**Expected results:**

- Precedence and bind parsing are deterministic; valid compose is preserved losslessly and malformed required data fails before listeners start.

<a id="tc-gos-entry-001-step-03"></a>
### Step 3: Inject failure and concurrency

Interrupt the primary dependency at its commit boundary, issue a conflicting concurrent operation, restore it, and retry once.

**Expected results:**

- At most one operation commits, failure cleanup releases all temporary resources, diagnostics identify the failed phase, and retry converges without duplicate state.

<a id="tc-gos-entry-001-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Restart the owning service where permitted and inspect state for this and an adjacent identity plus all collected output.

**Expected results:**

- Persisted and transient state follow policy, adjacent identities are unchanged, and no private material or credential appears in output.

## Postconditions

Remove run-scoped state and verify processes, files, devices, listeners, and allocations match baseline.
