<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-platform-006"></a>
# TC-GOS-PLATFORM-006: Systemd dependency and failure-action graph

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-platform-006](../../../../catalog/feature-audit.md#req-gos-platform-006)
- Risks: [risk-gos-platform-006](../../../../catalog/feature-audit.md#risk-gos-platform-006)
- Source: `os/common/rootfs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Treat `dstack-prepare`, Docker, containerd, and `app-compose` as boot/runtime
  graph nodes, not independently restartable leaf services. Verify their
  ordering, `Requires`/`After`, timeout, and failure-action properties through
  `systemctl show`/`systemctl cat`; do not restart them sequentially inside one
  SSH command. That can intentionally tear down the guest transport or invoke
  the guest reboot failure action and is not a valid service-restart matrix.
- Exercise dynamic restart/failure behavior only on a documented restartable
  leaf such as `dstack-guest-agent` or `dstack-gateway-checker`. Run each mutation as a
  separate bounded controller command. If a guest transport interruption is
  expected, poll VMM state and reconnect through the manifest route before the
  next assertion; an SSH reset alone is not a product failure.
- Keep Step 3 failure injection within the systemd behavior under test. Use a
  syntactically valid but nonexistent case-scoped unit name, or another invalid
  systemd operation that cannot mutate a real unit, and verify that systemd
  rejects it without changing the graph. Do not use malformed Guest API input:
  RPC parsing is unrelated to this case and is covered by the RPC cases.
- Do not stop or recreate `dstack-guest-agent.socket`. The fixture's TCP
  bridge bind-mounts the Unix socket inode, so recreating that socket invalidates
  only the observation transport. Interrupt `dstack-guest-agent.service` while
  leaving socket activation intact, or temporarily stop/continue its process,
  then verify service recovery through the unchanged socket.
- During the process interruption, a filesystem socket existence check or a
  repeated `systemctl start` is not the failed operation: both can succeed
  while the service process is stopped. Issue one bounded Tappd or DstackGuest
  RPC through the unchanged manifest endpoint, require it to time out or fail
  without a response, resume the process, and repeat that same RPC successfully.
- Use `values.systemd_graph_peer` as the adjacent lease-owned identity. Record
  its identity and running state before mutations and prove both are unchanged
  afterward; absence of that declared peer is a fixture defect, not isolation
  evidence.

## Objective

Verify systemd dependency and failure-action graph with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-gos-platform-006-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-gos-platform-006-step-02"></a>
### Step 2: Exercise supported and boundary paths

Start, fail, timeout, and restart prepare, simulator, guest-agent, Docker, app-compose, and WireGuard checker units.

**Expected results:**

- Ordering requirements prevent early consumers; optional absence does not reboot-loop; fatal failure follows documented action once with useful console diagnostics.

<a id="tc-gos-platform-006-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-gos-platform-006-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
