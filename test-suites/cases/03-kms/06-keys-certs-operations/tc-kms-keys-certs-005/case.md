<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keys-certs-005"></a>
# TC-KMS-KEYS-CERTS-005: CA persistence and near-expiry renewal

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-kms-keys-certs-005](../../../../catalog/feature-audit.md#req-kms-keys-certs-005)
- Risks: [risk-kms-keys-certs-005](../../../../catalog/feature-audit.md#risk-kms-keys-certs-005)
- Source: `dstack/kms/src/main_service.rs`, `dstack/kms/src/onboard_service.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the documented CA roles, normal-restart persistence, and near-expiry
renewal behavior for the root and temporary CA certificates.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-kms-keys-certs-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for temporary ca lifecycle.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-kms-keys-certs-005-step-02"></a>
### Step 2: Exercise the behavior

Retrieve temporary CA credentials as an authorized KMS peer and validate each
returned credential role. Restart the case-owned KMS with unchanged state and
verify exact certificate persistence. Then stop it, replace both public CA
certificates with one-day certificates made from the existing lease-owned keys,
and start it again.

**Expected results:**

- The returned temporary CA certificate matches the temporary CA private key and
  is a self-signed issuer used to mint onboarding RA-TLS client certificates.
  The separately returned root CA certificate is the persistent
  application-certificate trust root. An ordinary restart preserves both CA
  certificate fingerprints. A restart with near-expiry certificates renews both
  certificates while preserving their public keys and starts with a refreshed
  RPC certificate.

<a id="tc-kms-keys-certs-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query health and the authorized response, inspect component and peer logs, and attempt the same RPC using a client that lacks an accepted KMS self-attestation when enforcement is enabled by the fixture.

**Expected results:**

- Repeated authorized responses contain the final configured temporary and root
  CA certificates. When self-authorization enforcement is enabled, an
  unattested or unauthorized client is rejected before any CA material is
  returned. The service remains available and no credential content is written
  to evidence; retain only certificate fingerprints, public metadata, and
  validation outcomes.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
