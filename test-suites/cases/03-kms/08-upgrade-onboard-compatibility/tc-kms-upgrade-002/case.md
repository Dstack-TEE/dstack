<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-upgrade-002"></a>
# TC-KMS-UPGRADE-002: Direct 0.5.4 to 0.6.0 incompatibility is explicit

## Metadata

- Priority: P0
- Type: Compatibility, Upgrade, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-kms-upgrade-002](../../../../catalog/feature-audit.md#req-kms-upgrade-002)
- Risks: [risk-kms-upgrade-002](../../../../catalog/feature-audit.md#risk-kms-upgrade-002)
- Source: [PR #705 upgrade plan](https://github.com/Dstack-TEE/dstack/blob/203e09bcbce27e566f157d2b6ed4657eb949459a/docs/operations/kms-upgrade-plan.md)

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Confirm the known RA-TLS OID boundary is rejected for the documented reason and cannot be bypassed.

## Preconditions

1. The latest candidate VMM is installed with `qemu_single_pass_add_pages=true` and `qemu_pic=true`.
2. Source KMS root/CA and test-app derived-key fingerprints are recorded without exporting private keys.
3. Source and target `mrAggregated` plus the target image hash are authorized, and the source can download the target verifier archive.
4. At least two source KMS nodes remain available for rollback; destructive retirement is deferred until validation finishes.

## Test Data

Use pinned, digest-recorded images and binaries. “0.6.0” means the candidate under test. Record exact 0.5.x artifact tags/commits and QEMU/OVMF/ACPI-table versions in result overrides.

## Steps

<a id="tc-kms-upgrade-002-step-01"></a>
### Step 1: Run pre-flight measurement and trust checks

Capture source/target metadata, allowlists, image availability, `vm_config`, quote, CA and k256 public-key fingerprints. Run the age-appropriate `dstack-mr diagnose` when applicable.

**Expected results:**

- Both endpoint identities and the target image are authorized, target artifacts are downloadable, expected measurements reproduce the target quote, and no root or private key is exported.

<a id="tc-kms-upgrade-002-step-02"></a>
### Step 2: Execute the compatibility path

Attempt direct onboard of a legacy-mode 0.6.0 target from 0.5.4 with otherwise correct allowlists and artifacts.

**Expected results:**

- Onboard fails before key transfer with the old source unable to extract the versioned attestation (`No attestation provided` or its structured equivalent); source state and target uninitialized state remain unchanged.

<a id="tc-kms-upgrade-002-step-03"></a>
### Step 3: Verify rejection leaves both sides unchanged

Repeat the source metadata and key-fingerprint probes, inspect the target certificate directory and bootstrap state, and confirm clients continue using the retained 0.5.4 endpoints.

**Expected results:**

- The source CA/root and app-derived outputs are byte-for-byte unchanged, the target has not stored transferred root material, and existing clients remain healthy through the retained source endpoints.

<a id="tc-kms-upgrade-002-step-04"></a>
### Step 4: Prove the documented bridge is required

Remove the rejected target, then execute `tc-kms-upgrade-001` with the pinned 0.5.7 bridge and the same 0.5.4 source root. Do not weaken RA-TLS verification, patch OID handling, or copy key files manually.

**Expected results:**

- The bridge path succeeds with normal attested key transfer and preserves the recorded source identity, demonstrating that direct rejection is the compatibility boundary rather than a transient deployment failure.

## Postconditions

Keep the old nodes for the configured rollback window, remove failed bridge/target instances, and retain only redacted fingerprints, quotes, configs, and diagnostics.
