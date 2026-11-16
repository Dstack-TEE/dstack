<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certbot-005"></a>
# TC-GW-CERTBOT-005: Certbot certificate discovery and workdir ordering

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certbot-005](../../../../catalog/feature-audit.md#req-gw-certbot-005)
- Risks: [risk-gw-certbot-005](../../../../catalog/feature-audit.md#risk-gw-certbot-005)
- Source: `dstack/certbot/src/bot.rs`, `dstack/certbot/src/workdir.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify deterministic certificate discovery together with Certbot workdir archive
and rollback behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gw-certbot-005-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Create certificate directories in reverse creation order plus ordered complete
and incomplete archive entries in a case-owned workdir. Inspect canonical
paths, list certificates repeatedly, point live certificate/key links at a new
generation, and roll them back to the prior complete generation.

**Expected results:**

- Certificate paths and complete generations are returned in deterministic
  lexical order, incomplete entries are ignored, canonical live/archive paths
  are stable, and both live links can be rolled back to a matching prior
  generation.

<a id="tc-gw-certbot-005-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Write malformed account state beside an existing archive generation and query it through the candidate WorkDir API.

**Expected results:**

- Malformed credentials return an error without changing the existing archive generation.

<a id="tc-gw-certbot-005-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Run all observations in unique case-owned temporary directories, remove them, and retain only boolean/count evidence.

**Expected results:**

- Temporary workdirs are removed, no process or listener is created, and retained evidence contains no path, credential, or file content.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
