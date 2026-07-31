<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-internal-002"></a>
# TC-GW-INTERNAL-002: Gateway debug key generation artifact safety

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gw-internal-002](../../../feature-audit.md#req-gw-internal-002)
- Risks: [risk-gw-internal-002](../../../feature-audit.md#risk-gw-internal-002)
- Source: `dstack/gateway/src/gen_debug_key.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- The generator is the distinct Cargo binary `gen_debug_key`, not a `dstack-gateway` subcommand. Invoke the prepared shared-target `release/gen_debug_key` binary with exactly one simulator URL argument from the case manifest, and run it with the intended output directory as its working directory because it writes `debug_key.json`.
- Pass the simulator pRPC origin to `gen_debug_key`, not a route-prefixed client URL: when the manifest value ends in `/prpc`, remove that suffix before invocation because `PrpcClient` appends `GetQuote?json` itself.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify gateway debug key generation artifact safety exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use an isolated deployment with the relevant effective configuration and a clean run-scoped baseline.
2. Enable redacted process, file, RPC, and lifecycle evidence collection.

## Test Data

Include minimum, maximum, duplicate, missing, malformed, and cross-instance values appropriate to the behavior.

## Steps

<a id="tc-gw-internal-002-step-01"></a>
### Step 1: Record effective inputs and baseline

Capture effective configuration, input files/requests, existing processes/resources, and public status before the operation.

**Expected results:**

- Inputs resolve unambiguously to the intended test identity and no run-scoped output or resource exists.

<a id="tc-gw-internal-002-step-02"></a>
### Step 2: Exercise behavior and boundaries

Generate debug key data twice with target existing, unsafe permissions/path, interrupted write and production-config consumption attempt.

**Expected results:**

- Output is atomic, restricted, explicitly debug-labeled, not silently overwritten, and production startup refuses it.

<a id="tc-gw-internal-002-step-03"></a>
### Step 3: Inject failure and concurrency

Interrupt the primary dependency at its commit boundary, issue a conflicting concurrent operation, restore it, and retry once.

**Expected results:**

- At most one operation commits, failure cleanup releases all temporary resources, diagnostics identify the failed phase, and retry converges without duplicate state.

<a id="tc-gw-internal-002-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Restart the owning service where permitted and inspect state for this and an adjacent identity plus all collected output.

**Expected results:**

- Persisted and transient state follow policy, adjacent identities are unchanged, and no private material or credential appears in output.

## Postconditions

Remove run-scoped state and verify processes, files, devices, listeners, and allocations match baseline.
