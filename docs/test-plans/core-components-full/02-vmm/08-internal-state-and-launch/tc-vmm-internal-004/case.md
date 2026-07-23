<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-internal-004"></a>
# TC-VMM-INTERNAL-004: MR config and SNP host-data construction

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-vmm-internal-004](../../../feature-audit.md#req-vmm-internal-004)
- Risks: [risk-vmm-internal-004](../../../feature-audit.md#risk-vmm-internal-004)
- Source: `dstack/vmm/src/app/mr_config.rs`

## Objective

Verify mr config and snp host-data construction exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use an isolated deployment with the relevant effective configuration and a clean run-scoped baseline.
2. Enable redacted process, file, RPC, and lifecycle evidence collection.

## Test Data

Include minimum, maximum, duplicate, missing, malformed, and cross-instance values appropriate to the behavior.

## Steps

<a id="tc-vmm-internal-004-step-01"></a>
### Step 1: Record effective inputs and baseline

Capture effective configuration, input files/requests, existing processes/resources, and public status before the operation.

**Expected results:**

- Inputs resolve unambiguously to the intended test identity and no run-scoped output or resource exists.

<a id="tc-vmm-internal-004-step-02"></a>
### Step 2: Exercise behavior and boundaries

Generate TDX MR config IDs and SNP host_data across compose/image/app/GPU changes and repeated identical inputs.

**Expected results:**

- Outputs are deterministic, bind every documented input, match KMS/verifier computation, and a changed security input changes the expected digest.

<a id="tc-vmm-internal-004-step-03"></a>
### Step 3: Inject failure and concurrency

Interrupt the primary dependency at its commit boundary, issue a conflicting concurrent operation, restore it, and retry once.

**Expected results:**

- At most one operation commits, failure cleanup releases all temporary resources, diagnostics identify the failed phase, and retry converges without duplicate state.

<a id="tc-vmm-internal-004-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Restart the owning service where permitted and inspect state for this and an adjacent identity plus all collected output.

**Expected results:**

- Persisted and transient state follow policy, adjacent identities are unchanged, and no private material or credential appears in output.

## Postconditions

Remove run-scoped state and verify processes, files, devices, listeners, and allocations match baseline.
