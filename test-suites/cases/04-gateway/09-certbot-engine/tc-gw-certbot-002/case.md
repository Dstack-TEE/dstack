<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certbot-002"></a>
# TC-GW-CERTBOT-002: DNS-01 authorization propagation and cleanup

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certbot-002](../../../../catalog/feature-audit.md#req-gw-certbot-002)
- Risks: [risk-gw-certbot-002](../../../../catalog/feature-audit.md#risk-gw-certbot-002)
- Source: `dstack/certbot/src/acme_client.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify dns-01 authorization propagation and cleanup for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gw-certbot-002-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Issue a run-scoped order through candidate Certbot using case-owned Pebble and Cloudflare-compatible DNS services; observe TXT creation/removal, then repeat during provider outage and after recovery.

**Expected results:**

- Candidate Certbot creates and removes the challenge TXT record, successful issuance publishes the requested certificate, outage fails closed, recovery succeeds, and the adjacent zone remains untouched.

<a id="tc-gw-certbot-002-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Send two concurrent forced requests, make the DNS API unavailable for another forced request, restore it, and retry.

**Expected results:**

- Exactly one concurrent request renews, the outage returns an error without publishing a certificate, and the restored retry converges.

<a id="tc-gw-certbot-002-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Inspect the case-owned DNS model after issuance and recovery, verify both zones are empty, and remove the domain, credential, API server, Pebble, DNS service, and network.

**Expected results:**

- Challenge records are removed, the adjacent zone stays empty, evidence retains only counts/hashes/booleans, and every run-owned resource returns to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
