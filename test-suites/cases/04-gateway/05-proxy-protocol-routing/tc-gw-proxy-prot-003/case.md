<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-proxy-prot-003"></a>
# TC-GW-PROXY-PROT-003: TLS passthrough SNI address resolution

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-proxy-prot-003](../../../../catalog/feature-audit.md#req-gw-proxy-prot-003)
- Risks: [risk-gw-proxy-prot-003](../../../../catalog/feature-audit.md#risk-gw-proxy-prot-003)
- Source: `dstack/gateway/src/proxy/tls_passthough.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify tls passthrough sni address resolution across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-proxy-prot-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for tls passthrough sni address resolution.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gw-proxy-prot-003-step-02"></a>
### Step 2: Exercise the behavior

Connect valid app/instance domains, malformed SNI, unknown app, multiple hosts, IPv6, and backend failure.

**Expected results:**

- SNI maps to the correct online instance, failover is bounded, and unknown/malformed names cannot reach arbitrary addresses.

<a id="tc-gw-proxy-prot-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PRs #1245 and #1284)

- A ClientHello whose `server_name` is not a DNS name (it contains spaces and a run-scoped marker) is closed without reaching a backend, and the marker never appears in the Gateway log: the refusal reports only the name's length.
- A ClientHello whose `server_name` follows 6000 bytes of padding, past the listener's first 4096-byte read, is still routed to the instance backend, which receives the whole record and answers with a third marker.
- A ClientHello that puts its `server_name` behind 20000 bytes of padding, past one TLS record (16389 bytes), is refused without reaching a backend.
- The backend therefore sees exactly three routed connections.
- The `*.localhost` routing domain now comes from the certificate the fixture installs through `Admin.ImportCert` (PR #1239); without it every name here would be treated as a custom domain.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
