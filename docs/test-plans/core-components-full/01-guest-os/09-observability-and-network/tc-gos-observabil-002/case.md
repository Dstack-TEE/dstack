<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-observabil-002"></a>
# TC-GOS-OBSERVABIL-002: Socket activation and listener isolation

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-observabil-002](../../../feature-audit.md#req-gos-observabil-002)
- Risks: [risk-gos-observabil-002](../../../feature-audit.md#risk-gos-observabil-002)
- Source: `dstack/guest-agent/src/socket_activation.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The listener map is: systemd `ListenStream` index 0 is
  `/run/dstack.sock` for DstackGuest; index 1 is `/run/tappd.sock` for Tappd;
  the external TCP listener defaults to port `8090` and exposes public HTTP plus
  `/prpc/Worker.*`; GuestApi defaults to vsock any-CID port `8000` under
  `/api/GuestApi.*`. Do not infer the external listener from a Unix socket.
- Confirming activation survival, wrong-index behavior, bind conflicts, and
  partial-listener failure requires an isolated service instance whose sockets
  and process may be stopped/restarted. If every declared guest has
  `destructive_actions_allowed=false` and the manifest has no distinct
  case-scoped listener fixture, do not restart services, close sockets, alter
  units/configuration, or substitute a read-only listener snapshot; retain one
  bounded manifest observation and report the lifecycle matrix BLOCKED.

## Objective

Verify socket activation and listener isolation across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-observabil-002-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for socket activation and listener isolation.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-observabil-002-step-02"></a>
### Step 2: Exercise the behavior

Exercise systemd socket activation, internal Unix/vsock, external HTTPS, and GuestApi listeners.

**Expected results:**

- Each API appears only on its configured transport, accepts expected clients, and does not expose internal methods externally.

<a id="tc-gos-observabil-002-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
