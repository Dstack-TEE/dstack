<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-platform-002"></a>
# TC-GOS-PLATFORM-002: Local key provider sealing and identity isolation

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-platform-002](../../../../catalog/feature-audit.md#req-gos-platform-002)
- Risks: [risk-gos-platform-002](../../../../catalog/feature-audit.md#risk-gos-platform-002)
- Source: `dstack/local-key-provider/src`
- Prepared helper: `cases/01-guest-os/10-platform-services/tc-gos-platform-002/run.py` consumes the lease-owned primary/peer TDX guests and the configured local-key-provider endpoint; it never persists quotes, private keys, decrypted keys, or ciphertext.

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify local key provider sealing and identity isolation with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-gos-platform-002-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-gos-platform-002-step-02"></a>
### Step 2: Exercise supported and boundary paths

Generate report data from ephemeral X25519 public keys, request physical TDX quotes from two lease-owned guests with different app identities, and submit each quote to the configured SGX local-key-provider. Repeat the primary request and submit a tampered quote.

**Expected results:**

- Each response contains a provider quote and a sealed key decryptable only by the matching ephemeral private key. The decrypted primary key is stable for the same measured guest identity, the peer identity derives a different key, and a tampered quote returns no key.

<a id="tc-gos-platform-002-step-03"></a>
### Step 3: Exercise failure and recovery

Send invalid length framing and a structurally valid but tampered quote to the lease-visible provider endpoint, then repeat a valid request.

**Expected results:**

- Both invalid requests fail closed without key material, the provider remains available, and a repeated valid request succeeds. Diagnostics and stored evidence contain no quote, private key, decrypted key, ciphertext, or credential.

<a id="tc-gos-platform-002-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
