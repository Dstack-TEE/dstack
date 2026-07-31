<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-internal-005"></a>
# TC-VMM-INTERNAL-005: VM status protobuf projection and URL construction

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-vmm-internal-005](../../../feature-audit.md#req-vmm-internal-005)
- Risks: [risk-vmm-internal-005](../../../feature-audit.md#risk-vmm-internal-005)
- Source: `dstack/vmm/src/app/vm_info.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify vm status protobuf projection and url construction exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use an isolated deployment with the relevant effective configuration and a clean run-scoped baseline.
2. Enable redacted process, file, RPC, and lifecycle evidence collection.

## Test Data

Include minimum, maximum, duplicate, missing, malformed, and cross-instance values appropriate to the behavior.

For CLI operations, retain the ID returned by `CreateVm` and use that ID for `start`, `stop`, and `remove`; names are not lifecycle identifiers. When the effective fixture has port mapping disabled, omit port mappings and verify the projected empty list instead of making a custom-gateway row fail on an unrelated disabled feature. When enabled, port mappings use `PROTOCOL:HOST_PORT:VM_PORT` (for example, `tcp:8080:80`). Use forced stop for raw-substrate VMs without a reachable guest agent. Cleanup uses the `remove` command. Redaction checks compare actual case-owned sensitive values or private-key markers, not generic option words such as `token`.

## Steps

<a id="tc-vmm-internal-005-step-01"></a>
### Step 1: Record effective inputs and baseline

Capture effective configuration, input files/requests, existing processes/resources, and public status before the operation.

**Expected results:**

- Inputs resolve unambiguously to the intended test identity and no run-scoped output or resource exists.

<a id="tc-vmm-internal-005-step-02"></a>
### Step 2: Exercise behavior and boundaries

Project running/stopped/exited/brief/full VMs, empty optionals, custom/default gateway URLs, multiple networks and event timestamps.

**Expected results:**

- Every status field, optional presence, networking backend, app URL, uptime and event is correct without stale or empty-present values.

<a id="tc-vmm-internal-005-step-03"></a>
### Step 3: Inject failure and concurrency

Interrupt the primary dependency at its commit boundary, issue a conflicting concurrent operation, restore it, and retry once.

**Expected results:**

- At most one operation mutates state; concurrent duplicate `RemoveVm` calls may both return idempotent success when they converge to one removal. Failure cleanup releases all temporary resources, diagnostics identify the failed phase, and retry converges without duplicate state.

<a id="tc-vmm-internal-005-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Restart the owning service where permitted and inspect state for this and an adjacent identity plus all collected output.

**Expected results:**

- Persisted and transient state follow policy, adjacent identities are unchanged, and no private material or credential appears in output.

## Postconditions

Remove run-scoped state and verify processes, files, devices, listeners, and allocations match baseline.
