<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certbot-006"></a>
# TC-GW-CERTBOT-006: Certbot CLI once daemon config and signal lifecycle

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certbot-006](../../../feature-audit.md#req-gw-certbot-006)
- Risks: [risk-gw-certbot-006](../../../feature-audit.md#risk-gw-certbot-006)
- Source: `dstack/certbot/cli/src/main.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify certbot cli once daemon config and signal lifecycle for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gw-certbot-006-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Run the candidate CLI in forced once, non-forced once, and daemon modes against case-owned Pebble and DNS services; exercise successful/failing hooks, malformed config, persisted restart, SIGTERM, provider outage, and recovery.

**Expected results:**

- Forced once commits and invokes its hook, a failing post-commit hook does not roll back the certificate, malformed config fails, daemon iterations are paced, SIGTERM exits cleanly, and restart uses the persisted workdir.

<a id="tc-gw-certbot-006-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Make the DNS API unavailable during forced once mode, verify a nonzero exit, restore it, and retry using the same account and workdir.

**Expected results:**

- The outage attempt fails without a hook invocation, the restored attempt commits and invokes the hook once, and no challenge record remains.

<a id="tc-gw-certbot-006-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Stop daemon mode with SIGTERM, run non-forced once mode after restart, inspect bounded API activity and both DNS zones, then remove the workdir, API server, containers, and network.

**Expected results:**

- SIGTERM returns zero, restart does not spuriously invoke the hook, both DNS zones are empty, the adjacent zone is unchanged, and no process, listener, container, network, credential, certificate, or path is retained.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
