<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-boot-and-i-003"></a>
# TC-GOS-BOOT-AND-I-003: System and user configuration materialization

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-boot-and-i-003](../../../../catalog/feature-audit.md#req-gos-boot-and-i-003)
- Risks: [risk-gos-boot-and-i-003](../../../../catalog/feature-audit.md#risk-gos-boot-and-i-003)
- Source: `os/common/rootfs/dstack-prepare.sh`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- When the manifest records a healthy `role=candidate` guest, use its
  `ssh_argv`; a real hardware guest exceeds this case's SIMULATOR minimum. Do
  not start the user-space RPC simulator because it does not execute guest
  preparation.
- The input copy set is exactly `app-compose.json`, `.sys-config.json`, optional
  `.instance_info`, optional `.encrypted-env`, and optional `.user-config`.
  On the running guest, verify metadata and schema only under
  `/dstack/.host-shared`; never record `.appkeys.json`, decrypted environment
  values, seeds, private keys, or configuration values. The materialized
  consumer files are `/dstack/app-compose.json`, `/dstack/user_config`,
  `/dstack/agent.json`, and `/dstack/docker-compose.yaml` when the runner is
  Docker Compose.
- Use `systemctl show dstack-prepare.service` and the case-bounded journal to
  prove successful one-time materialization. For the invalid-input check, use
  an absent optional `.user-config` or a unique nonexistent path; do not alter
  the shared guest's host share or rerun preparation.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify system and user configuration materialization across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The runtime manifest records a dedicated case-scoped guest whose host share
   contains non-secret test `app-compose.json`, `.sys-config.json`,
   `.user-config`, and an `.encrypted-env` encrypted for that guest. A shared
   steady-state guest without those positive inputs is insufficient and the
   case is BLOCKED, not failed.
2. The guest is healthy and reachable through its manifest-recorded command
   interface. Its configuration may be inspected after preparation, but the
   case must not restart or rewrite an unrelated shared guest.
3. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier, a harmless `.user-config` marker, and one
non-secret encrypted environment marker. Record only marker hashes, field
names, file metadata, and redacted structure; never persist the decrypted value
or application keys as evidence.

## Steps

<a id="tc-gos-boot-and-i-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for system and user configuration materialization.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-boot-and-i-003-step-02"></a>
### Step 2: Exercise the behavior

Provide sys-config, user-config, compose, encrypted environment, and optional simulator config.

**Expected results:**

- Each file is copied to its documented location with restrictive ownership; missing optional files do not corrupt required state.

<a id="tc-gos-boot-and-i-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
