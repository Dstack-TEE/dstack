<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certbot-001"></a>
# TC-GW-CERTBOT-001: ACME account creation load and credential persistence

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certbot-001](../../../feature-audit.md#req-gw-certbot-001)
- Risks: [risk-gw-certbot-001](../../../feature-audit.md#risk-gw-certbot-001)
- Source: `dstack/certbot/src/acme_client.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify acme account creation load and credential persistence for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gw-certbot-001-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Create the candidate account against a case-owned Pebble directory, observe the account URI and quote on every Gateway node, force a renewal, replace the directory with an unreachable endpoint, restore it, and restart the primary Gateway.

**Expected results:**

- Every node reports the same non-empty account identity and quote, issuance succeeds, the unreachable directory fails closed, recovery succeeds, and the restarted node reports the original account identity.

<a id="tc-gw-certbot-001-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Issue two concurrent forced renewal requests, interrupt the DNS provider, restore it, and retry against the same persisted account.

**Expected results:**

- Exactly one concurrent request renews, the provider outage is rejected, and the restored retry renews without changing the cluster account identity.

<a id="tc-gw-certbot-001-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the primary candidate Gateway from its case-owned configuration, re-query public ACME information, verify the adjacent DNS zone, and remove all run-owned resources.

**Expected results:**

- The restarted node reports the original account identity, the adjacent DNS zone stays empty, credentials and account bodies are not retained, and all services, containers, network, domain, and credential state are cleaned.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
