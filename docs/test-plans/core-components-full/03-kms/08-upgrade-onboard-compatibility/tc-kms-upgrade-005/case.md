<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-upgrade-005"></a>
# TC-KMS-UPGRADE-005: Historical sources follow the verified lite-target compatibility matrix

## Metadata

- Priority: P0
- Type: Compatibility, Upgrade, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-kms-upgrade-005](../../../feature-audit.md#req-kms-upgrade-005)
- Risks: [risk-kms-upgrade-005](../../../feature-audit.md#risk-kms-upgrade-005)
- Source: live-version compatibility evidence correcting the stale lite-mode interpretation in the historical PR #705 upgrade plan

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Prove historical source KMS nodes apply their actual certificate-envelope and measurement-verification capabilities to lite/auto targets without bypassing image verification.

## Preconditions

1. The latest candidate VMM is installed with `qemu_single_pass_add_pages=true` and `qemu_pic=true`.
2. Source KMS root/CA and test-app derived-key fingerprints are recorded without exporting private keys.
3. Source and target `mrAggregated` plus the target image hash are authorized, and the source can download the target verifier archive.
4. At least two source KMS nodes remain available for rollback; destructive retirement is deferred until validation finishes.

## Test Data

Use pinned, digest-recorded images and binaries. “0.6.0” means the candidate under test. Record exact 0.5.x artifact tags/commits and QEMU/OVMF/ACPI-table versions in result overrides.

## Steps

<a id="tc-kms-upgrade-005-step-01"></a>
### Step 1: Run pre-flight measurement and trust checks

Capture source/target metadata, allowlists, image availability, `vm_config`, quote, CA and k256 public-key fingerprints. Run the age-appropriate `dstack-mr diagnose` when applicable.

**Expected results:**

- Both endpoint identities and the target image are authorized, target artifacts are downloadable, expected measurements reproduce the target quote, and no root or private key is exported.

<a id="tc-kms-upgrade-005-step-02"></a>
### Step 2: Execute the compatibility path

For 0.5.4, 0.5.8, and 0.5.11 sources, boot an otherwise authorized 0.6.0 target with `tdx_attestation_variant=lite` (and separately `auto` resolving to lite), serve the complete digest-verified target image archive, and attempt onboard.

**Expected results:**

- The 0.5.4 source rejects the versioned attestation certificate before root transfer. The 0.5.8 and 0.5.11 sources accept both targets after downloading the complete image archive and reproducing the same physical TDX measurements; unknown lite metadata is ignored by their backward-compatible `VmConfig` decoder, and no verification-disable path is used.

<a id="tc-kms-upgrade-005-step-03"></a>
### Step 3: Verify key, CA, application, and service continuity

Compare `GetMeta`, CA chain, root k256 public key, existing-app key/signature fingerprints, new-app provisioning, certificate signing, and authorization decisions through every surviving old/new KMS endpoint.

**Expected results:**

- All successfully onboarded nodes retain the original CA/root identity and return identical app-scoped material and policy decisions; old and new endpoints remain usable according to the stated matrix.

<a id="tc-kms-upgrade-005-step-04"></a>
### Step 4: Exercise failure, rollback, and retirement boundaries

Interrupt one hop before and after key transfer, remove the incomplete target, restore client routing to retained source nodes, then repeat successfully. Retire an old node only after all continuity checks pass.

**Expected results:**

- A failed hop does not alter the source root, clients can immediately use retained sources, repeated onboarding is safe, and retirement leaves at least two verified 0.6.0 root holders.

## Postconditions

Keep the old nodes for the configured rollback window, remove failed bridge/target instances, and retain only redacted fingerprints, quotes, configs, and diagnostics.
