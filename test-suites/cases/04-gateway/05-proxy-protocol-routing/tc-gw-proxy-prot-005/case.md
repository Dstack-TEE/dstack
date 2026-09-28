<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-proxy-prot-005"></a>
# TC-GW-PROXY-PROT-005: App-address namespace and content-addressed HTTPS

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-proxy-prot-005](../../../../catalog/feature-audit.md#req-gw-proxy-prot-005)
- Risks: [risk-gw-proxy-prot-005](../../../../catalog/feature-audit.md#risk-gw-proxy-prot-005)
- Source: `dstack/gateway/src/main_service.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify app-address TXT namespaces and content-name TLS passthrough across precedence, failure, cache, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-proxy-prot-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Start two case-owned DNS authorities with identical app-address records, a registered simulator identity, assigned address, Gateway listener, and backend without modifying the host resolver.

**Expected results:**

- The target component is healthy, both configured DNS servers receive queries, either server can resolve every valid record, and the baseline contains no run-scoped test object.

<a id="tc-gw-proxy-prot-005-step-02"></a>
### Step 2: Exercise the behavior

Resolve current, compatibility, and wildcard app-address records for app-, instance-, and content-style names; then exercise collisions, altered app IDs, malformed/missing records, positive-cache stability, expiry, and recovery.

**Expected results:**

- Current records take precedence over compatibility records, valid names reach only the registered app, and malformed, missing, wrong-app, or expired stale mappings are rejected.
- TLS ClientHello bytes remain end-to-end through passthrough. The Gateway does not terminate or validate the backend certificate on this path; HTTPS certificate and attestation validation is the client’s responsibility and is covered by the certificate/integration cases.

<a id="tc-gw-proxy-prot-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
