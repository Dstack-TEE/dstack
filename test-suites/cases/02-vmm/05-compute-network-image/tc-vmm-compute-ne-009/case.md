<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-compute-ne-009"></a>
# TC-VMM-COMPUTE-NE-009: Macvtap simulator launch and external connectivity

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: No
- Requirements: [req-vmm-compute-ne-009](../../../../catalog/feature-audit.md#req-vmm-compute-ne-009)
- Risks: [risk-vmm-compute-ne-009](../../../../catalog/feature-audit.md#risk-vmm-compute-ne-009)
- Source: `dstack/vmm/src/netd.rs`, `dstack/vmm/src/app/qemu.rs`, `dstack/vmm/src/vm_launcher.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify that a dedicated root netd prepares a macvtap device for an unprivileged
VMM, that the single-process launcher passes its character device as file
descriptor 3 and is replaced by QEMU, and that a mkosi development guest using
the `dstack-tdx` simulator obtains working LAN and external connectivity.
This simulator case is not evidence for TDX attestation or hardware isolation.

## Preconditions

1. The host supports KVM, QEMU, macvtap, and a case-owned VMM/supervisor runtime.
2. A mkosi development image is available in the candidate image store.
3. The selected parent interface is connected to a network that provides DHCP,
   DNS, and outbound HTTPS. If a physical interface is enslaved to a bridge,
   select the bridge rather than its busy member interface.
4. The executor can start one case-scoped netd as root and the VMM as its normal
   unprivileged service user. Do not reuse a production netd socket or VMM data
   path.
5. The external HTTPS probe endpoint is configurable and defaults to
   `https://example.com/`; no LAN address is hard-coded.

## Test Data

Use a unique run-scoped VM name, netd socket, VMM data/run path, supervisor
socket, and listener. Configure one network with `mode = "macvtap"`, the
fixture-selected parent interface, and `macvtap_mode = "private"`. Record the
parent, generated `dt...` interface, `/dev/tapN`, MAC address, VM ID, launcher
PID, QEMU PID, guest address, derived default gateway, and HTTPS endpoint.

## Steps

<a id="tc-vmm-compute-ne-009-step-01"></a>
### Step 1: Start isolated netd and VMM services

Start the candidate netd through a case-owned systemd-style activated Unix
socket, allowing only the VMM service UID. Also exercise the explicit socket
path fallback. Start the candidate VMM and supervisor with isolated data, run,
PID, log, and socket paths, then query the public status endpoint. Submit
deployment requests that attempt to select an undeclared network or override
the configured parent/mode.

**Expected results:**

- netd owns only the case-scoped socket and rejects an unauthorized UID.
- Socket activation consumes exactly the inherited listener and neither binds a
  second path nor accepts malformed descriptor state.
- Deployments may select a configured network by name but cannot inject or
  override host networking parameters.
- The unprivileged VMM reaches healthy status without using production runtime
  paths or a pre-existing netd instance.

<a id="tc-vmm-compute-ne-009-step-02"></a>
### Step 2: Create and launch a macvtap simulator guest

Create a VM from the mkosi development image with `--no-tee` and
`--simulated-tee dstack-tdx`, using the configured macvtap network. Observe the
netd response, host interface state, launch specification, and process tree
before accepting guest connectivity evidence.

**Expected results:**

- netd creates exactly one case-owned `dt...` macvtap on the selected parent,
  and `/dev/tapN` exists as a character device owned so the launcher can open it.
- The launch specification opens `/dev/tapN` as file descriptor 3; QEMU uses
  `-netdev tap,id=net0,fd=3` and the configured virtio-net device.
- For the single-process launch, QEMU replaces the launcher in place: the
  supervisor-observed PID remains the same and identifies QEMU, with no
  intermediate launcher process left running.
- The guest-visible interface MAC exactly matches the case-owned macvtap MAC.

<a id="tc-vmm-compute-ne-009-step-03"></a>
### Step 3: Verify guest LAN and external connectivity

Inside the guest, wait for DHCP, read the default route, and derive the gateway
from `ip route show default`. Verify the gateway has a reachable neighbor and
perform a bounded TCP/HTTP request to it. Resolve the configured external
endpoint hostname and perform a bounded HTTPS request to that endpoint. Do not
require `ping`; the development image may not provide it.

**Expected results:**

- The guest has a non-link-local DHCP IPv4 address and a default route on the
  macvtap-backed interface.
- The derived gateway has a reachable ARP/neighbor entry and accepts the bounded
  TCP/HTTP probe.
- DNS returns at least one address for the configured hostname and the external
  HTTPS request succeeds with a non-error HTTP response.
- Serial or guest-command evidence records the address, route, neighbor, DNS,
  HTTP results, and an unambiguous final connectivity pass marker.

<a id="tc-vmm-compute-ne-009-step-04"></a>
### Step 4: Stop, remove, and prove cleanup

Stop and remove the VM through the VMM API, then stop the case-owned VMM and
netd services. Inspect only the recorded case-owned process and network
identifiers.

**Expected results:**

- The supervisor observes QEMU exit and the VMM completes Stop and Remove.
- The recorded QEMU PID, `dt...` macvtap interface, `/dev/tapN`, VM directory,
  and case-owned sockets are absent.
- Unrelated host network interfaces, VMs, and services remain unchanged.

## Postconditions

Remove all case-owned VM, process, socket, and network resources. Preserve the
redacted netd/VMM logs, launch specification, host interface observations,
serial connectivity output, lifecycle responses, and cleanup observations in
the result artifacts.
