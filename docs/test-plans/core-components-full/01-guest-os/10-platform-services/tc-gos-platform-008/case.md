<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-platform-008"></a>
# TC-GOS-PLATFORM-008: Docker daemon and container privilege boundary

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-platform-008](../../../feature-audit.md#req-gos-platform-008)
- Risks: [risk-gos-platform-008](../../../feature-audit.md#risk-gos-platform-008)
- Source: `os/common/rootfs/docker.service.d`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Docker containers are not a security boundary from the application that owns
  the CVM. Compose is intentionally allowed to request privileged mode, host
  namespaces, devices, and guest-local mounts including the dstack sockets;
  those declarations are part of the measured app compose and authorization
  identity. Do not report access to the owning guest's sockets or Docker
  metadata as a failure.
- The enforced boundary is the CVM/VMM boundary. Compare a normal app and a
  separately measured privileged app: their compose hashes/app identities must
  differ, requested privileges must not appear in the normal app, and neither
  app may access the physical VMM host or the peer CVM's filesystem, sockets,
  containers, or identity. Test resource limits only when declared in that
  app's measured compose.
- The case manifest must provide `values.docker_boundary.normal` and
  `values.docker_boundary.privileged`, each with its own lease-owned VM, SSH
  command, instance identity, and compose hash. The normal compose contains a
  constrained `boundary-target`; the privileged compose declares its elevated
  settings. If these two measured fixtures are absent, do not substitute two
  ad-hoc `docker run` commands inside one VM because that cannot prove compose
  identity binding or cross-CVM isolation.

## Objective

Verify docker daemon and container privilege boundary with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-gos-platform-008-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-gos-platform-008-step-02"></a>
### Step 2: Exercise supported and boundary paths

Launch separately measured normal and privileged compose applications requesting host mounts, devices, privileged mode, namespaces, capabilities, and resource limits.

**Expected results:**

- Declared privileges and limits are honored inside the owning CVM, the normal
  app does not gain undeclared privileges, compose/app identity binds the
  difference, and neither app reaches the VMM host or peer CVM state.

<a id="tc-gos-platform-008-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-gos-platform-008-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
