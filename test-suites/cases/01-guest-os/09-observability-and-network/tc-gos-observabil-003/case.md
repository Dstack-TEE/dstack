<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-observabil-003"></a>
# TC-GOS-OBSERVABIL-003: Gateway checker startup contract and WireGuard isolation

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gos-observabil-003](../../../../catalog/feature-audit.md#req-gos-observabil-003)
- Risks: [risk-gos-observabil-003](../../../../catalog/feature-audit.md#risk-gos-observabil-003)
- Source: `dstack/dstack-util/src/gateway_checker.rs`, `os/common/rootfs/dstack-gateway-checker.service`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The checker is `dstack-util gateway-checker --work-dir <dir>`, run by
  `dstack-gateway-checker.service`. It replaced the former `wg-checker.sh`.
- Its refresh timing (180s periodic re-registration, 180s handshake staleness,
  and the 30s/60s/120s retry backoff for a missing WireGuard config) is a pure
  decision function covered by unit tests in `dstack/dstack-util/src/gateway_checker.rs`.
  Do not re-derive that matrix here: an accelerated clock in the guest can only
  restate those tests less reliably.
- What unit tests cannot reach is the boundary between the process and systemd,
  which is what this case covers. The checker encodes each unrecoverable startup
  condition as an exit code, and the unit must honour it:
  - An app that never enabled dstack-gateway has nothing to supervise, so the
    checker exits 0. With `Restart=on-failure` systemd then leaves it alone;
    `Restart=always` would respawn it every `RestartSec` for the life of every
    gateway-less CVM.
  - A missing gateway app id or gateway URL is a deployment mistake fixed for
    the lifetime of the VM. The checker exits with `EXIT_MISCONFIGURED`, which
    the unit pins in `RestartPreventExitStatus`. That stops the respawn while
    leaving the unit in `failed` state, so the mistake stays visible. Read the
    expected code from the product source; do not restate it.
  - Any other non-zero exit is treated as transient and is retried.
- Registration failure is no longer fatal to boot, so the guest reports
  `boot.error` to the host while it has no route and retracts it once the
  checker registers. The VMM surfaces that through `VmInfo.boot_error`.
- This case needs an isolated WireGuard interface, permission to create a
  network namespace, and the guest's own `dstack-util` and unit. Never alter
  networking, gateway registration, `/etc/wireguard`, services, routes, DNS, or
  interfaces on a guest with `destructive_actions_allowed=false`. If no distinct
  case-scoped network fixture is declared, preserve one bounded manifest
  observation and report the behavior BLOCKED.

## Objective

Verify that the gateway checker maps each unrecoverable startup condition to the exit code its unit honours, and that a real WireGuard interface can be configured and observed in isolation.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-observabil-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for wireguard configuration and checker recovery.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-observabil-003-step-02"></a>
### Step 2: Exercise the behavior

Build an isolated WireGuard interface, then run the packaged checker against synthesized host-shared inputs for each startup condition.

**Expected results:**

- Addresses, peers, routes, DNS, and the zero-handshake baseline are observable without duplicate interfaces or leaked keys.
- A gateway-disabled app makes the checker exit 0 rather than poll.
- A missing gateway app id and a missing gateway URL each make it exit with the code the unit pins in `RestartPreventExitStatus`.
- The installed unit is loaded with `Restart=on-failure`, inhibits restart for exactly that code, and runs the `dstack-util` subcommand rather than the removed shell script.

<a id="tc-gos-observabil-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
