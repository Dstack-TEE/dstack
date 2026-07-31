<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certbot-003"></a>
# TC-GW-CERTBOT-003: Cloudflare DNS record API boundaries

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certbot-003](../../../feature-audit.md#req-gw-certbot-003)
- Risks: [risk-gw-certbot-003](../../../feature-audit.md#risk-gw-certbot-003)
- Source: `dstack/certbot/src/dns01_client/cloudflare.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify cloudflare dns record api boundaries for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gw-certbot-003-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Run the candidate Cloudflare client add/list/remove paths for TXT and CAA records against a case-owned API model, then repeat with an invalid token and a provider outage.

**Expected results:**

- TXT and CAA records are created, listed, and removed in the selected zone; invalid authorization and provider errors fail without exposing credentials.

<a id="tc-gw-certbot-003-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Reject an invalid API token, force the DNS provider to return an error, restore the provider, and rerun the complete mutation matrix.

**Expected results:**

- Invalid authorization and outage attempts return nonzero, and the restored client completes the TXT/CAA matrix without retained records.

<a id="tc-gw-certbot-003-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Inspect both modeled zones after the recovery run, stop the case-owned API server, and verify that all records and the server thread are gone.

**Expected results:**

- Both modeled zones are empty, the adjacent zone remains untouched, the API server is reaped, and retained evidence contains no credential, domain, record, or endpoint values.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
