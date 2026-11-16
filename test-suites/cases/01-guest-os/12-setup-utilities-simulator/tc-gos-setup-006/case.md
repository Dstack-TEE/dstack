<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-006"></a>
# TC-GOS-SETUP-006: KMS endpoint normalization and provider inventory

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-006](../../../../catalog/feature-audit.md#req-gos-setup-006)
- Risks: [risk-gos-setup-006](../../../../catalog/feature-audit.md#risk-gos-setup-006)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Treat `values.boot_observation` as the authoritative initial VM state. For a fresh observation, execute `values.vm_info_argv` exactly; use `values.list_vms_argv` only for a fleet listing. The VMM CLI has no `status` subcommand, so never invent or infer one.

## Objective

Verify KMS RPC endpoint normalization and local-provider inventory requirements.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-006-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Exercise endpoint spellings with and without a trailing slash or `/prpc`, then
independently validate local and TPM key-provider inventory requirements.

**Expected results:**

- Every endpoint resolves to exactly one `/prpc` suffix. Local and TPM providers
  do not require a remote KMS inventory, while KMS routing requires at least one
  endpoint.

<a id="tc-gos-setup-006-step-02"></a>
### Step 2: Verify invalid inventory handling

Validate empty KMS inventories for KMS, local, and TPM provider selections.

**Expected results:**

- KMS selection rejects an empty inventory, while local and TPM selections do
  not acquire an unnecessary remote dependency.

<a id="tc-gos-setup-006-step-03"></a>
### Step 3: Verify bounded execution and cleanup

Run the focused candidate tests with the prepared Cargo target and retain only
the test count and boolean observations.

**Expected results:**

- Exactly the endpoint-normalization and provider-inventory tests pass; no
  endpoint credential or key material is retained.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
