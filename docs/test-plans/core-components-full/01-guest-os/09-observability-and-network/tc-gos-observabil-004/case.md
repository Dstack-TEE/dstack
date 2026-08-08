<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-observabil-004"></a>
# TC-GOS-OBSERVABIL-004: System network and resource telemetry

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-observabil-004](../../../feature-audit.md#req-gos-observabil-004)
- Risks: [risk-gos-observabil-004](../../../feature-audit.md#risk-gos-observabil-004)
- Source: `dstack/guest-agent/src/guest_api_service.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- `NetworkInfo` intentionally reports only `dstack-wg0`, `enp*`, and `eth*`
  interfaces; Docker bridges are excluded for privacy. Each address includes its
  prefix, counters are cumulative received/transmitted bytes and receive/send
  errors, DNS entries are `nameserver` values from `/etc/resolv.conf`, and
  gateways are current default gateways. WireGuard command output is returned
  separately as `wg_info`.
- `SysInfo` reports memory/swap and disk sizes in bytes, uptime in seconds, and
  load averages multiplied by 100 and truncated to integers. Disks are limited
  to configured `data_disks` and sorted by mount point. `ListContainers`
  includes stopped and running containers.
- `SysInfo`, `NetworkInfo`, and `ListContainers` belong to the private
  `GuestApi` service bound to guest vsock port 8000; they are not methods on
  the public `DstackGuest` listener. Call them through the case manifest's
  `services.ProxiedGuestApi.url`, replacing `{method}` and sending
  `{"id":"<values.vm_id>"}`. A `Service not found` response from
  `services.DstackGuest` proves the wrong listener was selected and is not a
  product telemetry result.
- The complete transition matrix requires an isolated guest where interfaces,
  routes, DNS, CPU/load, memory pressure, disks, swap, and containers may be
  safely added and removed. Do not change any of these on a guest with
  `destructive_actions_allowed=false`; a read-only snapshot cannot prove
  transition or disappearance behavior. Without a distinct case-scoped
  telemetry fixture, retain one bounded manifest observation and report the
  matrix BLOCKED.
- The candidate guest uses BusyBox `ip`; its kernel does not provide the dummy
  link type. Create the removable `eth*` observation interface as a veth pair
  (`ip link add ethobs... type veth peer name veth...`) and remove the pair
  after the changed snapshot. Do not use `ip link add ... type dummy` and do
  not treat that known unsupported link type as a product failure.
- Before creating `ethobs...`, write a run-scoped `.network` file under
  `/run/systemd/network` that matches only that interface and sets
  `[Link] Unmanaged=yes`, then call `networkctl reload`. Otherwise networkd's
  generic wired policy races the test and flushes the synthetic IPv4 address
  and route. After deleting the interface, unlink the file and reload again;
  do not stop networkd because that removes the fixture's SSH connectivity.
- systemd may also rewrite `/etc/resolv.conf` during the snapshot. Copy its
  baseline to a run-scoped file, append the test nameserver there, bind-mount
  that file over `/etc/resolv.conf` for the changed observation, then unmount
  it and unlink the file during cleanup. Directly appending to the managed
  file is not a stable DNS transition.
- The default ZFS data volume rejects swap files as having holes, even when
  filled from `/dev/urandom`. To exercise swap telemetry without changing the
  storage fixture, create a bounded file under `/dev/shm`, attach it with
  `losetup -f --show`, run `mkswap` and `swapon` on the loop block device, then
  clean up in this order: `swapoff`, `losetup -d`, and unlink the backing file.

## Objective

Verify system network and resource telemetry across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-observabil-004-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for system network and resource telemetry.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-observabil-004-step-02"></a>
### Step 2: Exercise the behavior

Change interfaces, routes, DNS, load, memory, disk, swap, and container set.

**Expected results:**

- GuestApi reports complete current values with correct units, prefixes, counters, and disappearance of removed resources.

<a id="tc-gos-observabil-004-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
