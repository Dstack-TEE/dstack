<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-auth-009"></a>
# TC-KMS-AUTH-009: Contract event audit completeness

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-auth-009](../../../feature-audit.md#req-kms-auth-009)
- Risks: [risk-kms-auth-009](../../../feature-audit.md#risk-kms-auth-009)
- Source: `dstack/kms/auth-eth/contracts`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify additive contract audit events identify the actor, policy, affected value, and resulting enabled state well enough to reconstruct KMS and application authorization state across invalid mutations, upgrades, and canonical reorg recovery.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-kms-auth-009-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-kms-auth-009-step-02"></a>
### Step 2: Exercise supported and boundary paths

Exercise KMS and app allowlist additions/removals, boolean policy changes, app registration, gateway identity, and implementation upgrade, then reconstruct effective authorization from the ordered legacy plus additive audit events.

**Expected results:**

- Events include actor, affected identity or public-value hash, policy domain, and new state without secrets; reconstructed state equals contract queries and the implementation slot.

<a id="tc-kms-auth-009-step-03"></a>
### Step 3: Exercise failure and recovery

Attempt an unauthorized policy mutation, then use deterministic EVM snapshot/revert to orphan one valid event and apply a different canonical mutation.

**Expected results:**

- The unauthorized call emits no audit event and leaves no partial state; the orphan event is discarded after revert and the canonical event alone rebuilds the queried state.

<a id="tc-kms-auth-009-step-04"></a>
### Step 4: Verify isolation and persistence

Execute all exact rows in a second fresh Foundry process using the same committed contracts and isolated commit-keyed compiler outputs.

**Expected results:**

- Both fresh processes pass all exact rows; retained evidence contains only counts, durations, coverage labels, tool version, commit, and output hashes.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
