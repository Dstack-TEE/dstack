<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certbot-001"></a>
# TC-GW-CERTBOT-001: ACME account creation load and credential persistence

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certbot-001](../../../../catalog/feature-audit.md#req-gw-certbot-001)
- Risks: [risk-gw-certbot-001](../../../../catalog/feature-audit.md#risk-gw-certbot-001)
- Source: `dstack/certbot/src/acme_client.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
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

## Post-baseline regression coverage (PR #1138)

- Rotation, CAA reconciliation, and first-use ACME account registration now share one cluster-wide lock stored in WaveKV, and first-use registration re-reads the credentials under that lock and adopts an account another node already registered.
- With the case-owned Cloudflare API blocked, call `Admin.RotateAcmeCredentials` on node 1 and wait until its DNS-provider preflight reaches the API. After 3 seconds, which covers WaveKV replication at the fixture's 1-second sync interval, call `Admin.SetCaa` on node 2. Expected: node 2 answers with HTTP status 400 or higher naming the `shared ACME lock`, and sends no Cloudflare API request. After the block is released, the rotation completes, and the existing rotation expectations hold: every node reports the new account and the CAA records are re-pinned to it.
- Every node still reports the same `account_uri` after the initial issuance, which shows the cluster registered a single shared account.

## Post-baseline regression coverage (PR #1262)

- Startup no longer issues certificates for configured domains before the listeners bind; issuance runs in the background certbot task, and every ACME request is bounded to 30 seconds.
- Before the primary restart, point the cluster's certbot configuration at a case-owned ACME directory that accepts TCP connections and never answers, and add a second run-scoped ZT domain (`stall-<lease>.test`) that has no certificate. The restarted primary must accept connections on its RPC port within 15 seconds. The old startup path would wait on that directory indefinitely.
- Then restore the case ACME URL and delete the second domain; both calls return HTTP 200 and the persisted account check below is unchanged.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
