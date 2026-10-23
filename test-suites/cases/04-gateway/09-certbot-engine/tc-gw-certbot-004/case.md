<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certbot-004"></a>
# TC-GW-CERTBOT-004: Certificate renewal threshold force and hook

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certbot-004](../../../../catalog/feature-audit.md#req-gw-certbot-004)
- Risks: [risk-gw-certbot-004](../../../../catalog/feature-audit.md#risk-gw-certbot-004)
- Source: `dstack/certbot/src/bot.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify certificate renewal threshold force and hook for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gw-certbot-004-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Issue a certificate through case-owned Pebble and DNS services, immediately request a non-forced renewal below the configured threshold, force renewal, send two concurrent forced requests, interrupt DNS, restore it, and observe Gateway in-memory publication.

**Expected results:**

- The below-threshold request is a no-op, forced requests renew, exactly one concurrent request wins, outage fails closed, recovery renews, and the committed certificate is loaded in memory.

<a id="tc-gw-certbot-004-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Make the DNS provider fail during a forced renewal, verify rejection, restore it, and retry while retaining the prior published certificate.

**Expected results:**

- The outage attempt does not publish a partial result, the retry converges, and Gateway remains healthy throughout.

<a id="tc-gw-certbot-004-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Query the committed certificate status after initial issuance and recovery, verify it is loaded in memory, check the adjacent DNS zone, and remove all case resources.

**Expected results:**

- Publication is observable only after successful commit, the adjacent zone remains empty, no certificate or credential body is retained, and all domain, credential, service, container, and network state is cleaned.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
