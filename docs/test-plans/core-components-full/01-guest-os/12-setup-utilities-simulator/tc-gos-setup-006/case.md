<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-006"></a>
# TC-GOS-SETUP-006: KMS URL selection failover and local-provider orthogonality

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-006](../../../feature-audit.md#req-gos-setup-006)
- Risks: [risk-gos-setup-006](../../../feature-audit.md#risk-gos-setup-006)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Objective

Verify kms url selection failover and local-provider orthogonality for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-006-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Request app keys across ordered healthy/timeout/wrong-cert/deny KMS URLs, then independently select local key provider and TPM requirements.

**Expected results:**

- Remote failover preserves one verified app identity; local-provider selection does not change simulated-TEE choice, and neither path silently falls back to plaintext/random keys.

<a id="tc-gos-setup-006-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-setup-006-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
