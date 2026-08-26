<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-internal-002"></a>
# TC-GW-INTERNAL-002: Gateway on-demand TLS key artifact safety

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gw-internal-002](../../../../catalog/feature-audit.md#req-gw-internal-002)
- Risks: [risk-gw-internal-002](../../../../catalog/feature-audit.md#risk-gw-internal-002)
- Source: `dstack/gateway/src/main.rs:gen_certs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- The legacy `gen_debug_key` binary, `debug_key.json`, `core.debug.key_file`, and direct KMS signing path were removed. Confirm they remain absent rather than attempting to prepare or invoke them.
- The current Gateway requests a fresh TLS key and certificate chain from DstackGuest during startup, publishes the configured key, certificate, and mutual-CA destinations with restrictive permissions, and must fail before publishing destination artifacts when DstackGuest is unavailable.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify Gateway on-demand DstackGuest TLS-key generation and artifact safety match the current source-defined behavior across normal and dependency-failure paths, with no legacy pre-generated debug-key mechanism.

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

Inspect the live startup artifacts generated through DstackGuest and start an isolated candidate with fresh destination paths and an unavailable DstackGuest dependency.

**Expected results:**

- The live key, certificate chain, and mutual CA are complete and mode `0600`; no legacy generator, binary, configuration field, or `debug_key.json` exists.

<a id="tc-gw-internal-002-step-03"></a>
### Step 3: Inject failure and concurrency

Make DstackGuest unavailable before the isolated candidate requests its TLS key and inspect all fresh destination paths after the bounded startup failure.

**Expected results:**

- Startup fails nonzero before any key, certificate-chain, mutual-CA, or temporary destination artifact is published.

<a id="tc-gw-internal-002-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Restart the owning service where permitted and inspect state for this and an adjacent identity plus all collected output.

**Expected results:**

- Persisted and transient state follow policy, adjacent identities are unchanged, and no private material or credential appears in output.

## Postconditions

Remove run-scoped state and verify processes, files, devices, listeners, and allocations match baseline.
