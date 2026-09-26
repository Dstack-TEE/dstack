<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-proxy-prot-006"></a>
# TC-GW-PROXY-PROT-006: Connection limits timeouts and recycling

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-proxy-prot-006](../../../../catalog/feature-audit.md#req-gw-proxy-prot-006)
- Risks: [risk-gw-proxy-prot-006](../../../../catalog/feature-audit.md#risk-gw-proxy-prot-006)
- Source: `dstack/gateway/src/proxy/io_bridge.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify per-app aggregate connection limits, handshake/idle/total timeouts, half-close draining, connection-counter recycling, and recovery.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-proxy-prot-006-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for connection limits timeouts and recycling.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gw-proxy-prot-006-step-02"></a>
### Step 2: Exercise the behavior

Hold the configured per-app connection limit across the selected backend set, attempt one excess connection, then exercise handshake, idle, and total timeouts plus a bidirectional half-close.

**Expected results:**

- The aggregate per-app limit rejects excess work without forwarding it, closing admitted connections releases their counters, half-close drains the reverse direction, each timeout is bounded, and recovery leaves no task or socket leak.

<a id="tc-gw-proxy-prot-006-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PR #1245)

- The connection limit is checked and taken in one atomic step. Six routed connections are released together from a barrier against `max_connections_per_app = 2`: exactly two reach the backend, and the other four close without data within 0.4 seconds, which keeps the admitted relays inside the 1-second idle timeout while they are classified.
- A relay whose client stops reading is reaped by the idle timeout instead of the 5-hour total, on both the splice and the adaptive kTLS paths, and a writer that accepts no bytes ends the relay instead of spinning a core. These need a client that stalls against a full socket buffer and a zero-length writer, which the live fixture cannot produce deterministically, so the harness runs exactly these candidate tests and requires all four to pass: `proxy::splice::tests::a_client_that_stops_reading_is_reaped_by_the_idle_timeout`, `proxy::adaptive_ktls::tests::a_client_that_stops_reading_is_reaped_by_the_idle_timeout`, `proxy::io_bridge::tests::a_writer_that_accepts_no_bytes_is_an_error_not_a_spin` and `proxy::tls_passthough::tests::the_connection_limit_check_takes_the_slot`.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
