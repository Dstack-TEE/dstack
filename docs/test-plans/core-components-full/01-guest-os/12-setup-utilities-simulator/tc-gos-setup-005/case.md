<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-005"></a>
# TC-GOS-SETUP-005: MR config ID verification before provisioning

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-005](../../../feature-audit.md#req-gos-setup-005)
- Risks: [risk-gos-setup-005](../../../feature-audit.md#risk-gos-setup-005)
- Source: `dstack/dstack-util/src/system_setup/config_id_verifier.rs`

## Objective

Verify mr config id verification before provisioning for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-005-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Verify matching/mismatching/malformed MR config IDs across TDX/SNP and changed compose, image, GPU, CPU and vm_config inputs.

**Expected results:**

- Only the exact expected ID permits provisioning; mismatch identifies bound input and no KMS/local key is consumed.

<a id="tc-gos-setup-005-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-setup-005-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
