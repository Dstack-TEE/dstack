<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-build-002"></a>
# TC-VER-BUILD-002: Verifier default configuration and CLI override precedence

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-ver-build-002](../../../feature-audit.md#req-ver-build-002)
- Risks: [risk-ver-build-002](../../../feature-audit.md#risk-ver-build-002)
- Source: `dstack/verifier/dstack-verifier.toml`

## Objective

Verify verifier default configuration and cli override precedence for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

The `verifier` portion of [`configuration-inventory.json`](../../../configuration-inventory.json) is mandatory test data. Exercise every listed field at its implicit default, an explicit valid value, boundary-invalid values, an unknown sibling field, and after restart.

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-ver-build-002-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Run default/file/environment/CLI combinations for image URL/cache/trust/collateral/ACPI/timeouts, with unknown and invalid values.

**Expected results:**

- Precedence is deterministic and observable, unsafe/missing required trust config fails at startup, and overrides cannot silently disable required verification.

<a id="tc-ver-build-002-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-ver-build-002-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
