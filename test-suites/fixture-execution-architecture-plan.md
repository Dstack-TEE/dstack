<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="fixture-execution-architecture-plan"></a>
# Fixture and Dual-Executor Architecture Implementation Plan

## 1. Objective

Upgrade `dstack-test` from an Agent-only sequential runner into a test-plan
controller that:

1. provisions an isolated, leased fixture before each case;
2. supports either an Agent executor or a declared automation entrypoint;
3. keeps fixture setup distinct from actions under test;
4. streams execution, step, evidence, attachment, and cleanup state to the UI;
5. forcibly reclaims all case-owned resources after success, failure, timeout,
   Stop, or controller restart;
6. never reuses long-lived shared CVMs for state-changing release tests; and
7. preserves the existing result, evidence, report, and package contracts.

## 2. Current run state and immediate safety decision

The active physical TDX host round was stopped before this refactor:

- Run ID: `physical-tdx-optimized-20260723T182727Z`
- Last observed counts after Stop: PASS 19, FAIL 9, BLOCKED 37,
  INCOMPLETE 1, PENDING 295.
- The interrupted case was `tc-gos-setup-001`.
- Physical-host reboot remains forbidden.
- The existing candidate and legacy CVMs are long-lived development CVMs and
  must not be reused as mutable fixtures.

Resume the same run ID only after the new runner has passed its fixture,
script-executor, Stop/Start, live-log, and cleanup tests.

## 3. Case schema

Extend each indexed case with optional `execution`, `fixture`, and
`actions_under_test` values.

```json
{
  "id": "tc-vmm-vmm-001",
  "execution": {
    "entrypoint": "shared/automation/run-test.py",
    "args": [],
    "timeout_seconds": 600
  },
  "fixture": {
    "profile": "vmm-empty-control-plane",
    "initial_state": "vmm-running-no-vms",
    "capabilities": ["create_vm", "remove_vm"],
    "versions": {
      "vmm": "candidate",
      "guest": "candidate",
      "kms": "candidate",
      "gateway": "candidate"
    }
  },
  "actions_under_test": ["Vmm.CreateVm"]
}
```

Executor selection is intentionally implicit:

- no `execution.entrypoint`: use the configured Codex/Claude Agent;
- `execution.entrypoint` present: execute the script directly and do not start
  an Agent.

Validation requirements:

- entrypoint and all referenced files resolve inside the plan root;
- no symlink escape;
- entrypoint is a regular executable file with a valid shebang;
- args are an array of strings;
- timeout is a positive bounded integer;
- setup is forbidden from invoking any declared action under test.

## 4. Fixture profiles

Add a profile registry under `test-suites/shared/fixtures/`.
Initial profiles:

- `guest-readonly`
- `guest-lifecycle`
- `no-tee-dev`
- `storage-lifecycle`
- `network-lifecycle`
- `container-observability`
- `multi-identity`
- `vmm-empty-control-plane`
- `vmm-raw-substrate`
- `kms-onboard`
- `gateway-cluster`
- `gpu-policy`
- `cross-platform-attestation`

Classify every case as one of:

- `ready-target`
- `empty-control-plane`
- `specified-initial-state`
- `raw-substrate`

Each profile declares capabilities, versions, resource bounds, initial-state
checks, readiness checks, destructive scope, maximum TTL, provider, collection,
and teardown behavior.

## 5. Fixture manager and providers

Add the following modules:

```text
test-suites/runner/
├── fixtures.py
├── leases.py
├── resources.py
└── providers/
    ├── base.py
    ├── process.py
    ├── vmm.py
    ├── guest.py
    ├── simulator.py
    ├── storage.py
    ├── network.py
    ├── kms.py
    ├── gateway.py
    └── hardware.py
```

Provider contract:

```python
class FixtureProvider:
    def allocate(self, request) -> Lease: ...
    def prepare(self, lease) -> CaseRuntimeManifest: ...
    def verify_initial_state(self, lease) -> CheckResult: ...
    def collect(self, lease) -> list[Artifact]: ...
    def destroy(self, lease) -> CleanupResult: ...
```

The lab manager is out-of-band infrastructure, not the SUT. For VMM API tests,
the lab manager launches an isolated candidate VMM with an empty namespace;
the case then invokes the real VMM API. For VMM startup tests, the fixture only
provides binary, config, ports, directories, images, and dependencies; the case
starts the SUT VMM itself.

## 6. Leases and ownership journal

Persist each lease at:

```text
<plan>/results/<run-id>/leases/<lease-id>.json
```

Record every process, VM, volume, port, CID, network namespace, container,
data directory, gateway registration, and remote hardware allocation
immediately after creation. Include owner case, provider, creation time, TTL,
cleanup handle, and current cleanup state.

On server startup, scan unfinished leases and reconcile/reclaim them. Cleanup
must work independently of the Agent or script and run after normal completion,
FAIL, BLOCKED, timeout, Stop, crash, or restart.

## 7. Runtime manifests

Keep the run-wide immutable manifest for candidate digests, version catalog,
lab capabilities, provider configuration, and hardware pools.

Generate a case-specific manifest at:

```text
<plan>/results/<run-id>/cases/<chapter>/<section>/<case-id>/fixture/runtime-manifest.json
```

It contains only that case's lease, fixture profile, endpoints, allocated
resources, initial state, permissions, versions, cleanup handle, and expiration.
The executor receives it as `DSTACK_TEST_CASE_MANIFEST`.

## 8. Controller lifecycle

Replace the simple state model with:

```text
PENDING
→ WAITING_FOR_RESOURCE
→ PROVISIONING
→ VERIFYING_FIXTURE
→ READY
→ RUNNING
→ COLLECTING
→ CLEANING
→ terminal result
```

Distinguish:

- `BLOCKED`: required capability cannot be supplied;
- `INFRA_ERROR`: capability should exist but provisioning/check/cleanup failed;
- `INCOMPLETE`: executor was interrupted or produced no valid final result;
- `FAIL`: tested behavior contradicted the expected result.

A Stop request stops the complete current round, terminates the verified process
group, preserves the attempt as INCOMPLETE, collects diagnostics, and destroys
the fixture. A later explicit Start may archive the incomplete attempt and run
it again with a new lease. No automatic retry occurs within one round.

## 9. Script executor

When a case declares `execution.entrypoint`, `run-case` invokes it directly via
an argv array (`shell=False`) with the case directory as cwd. Environment:

```text
DSTACK_TEST_RUN_ID
DSTACK_TEST_CASE_ID
DSTACK_TEST_PLAN_DIR
DSTACK_TEST_CASE_DIR
DSTACK_TEST_RESULT_DIR
DSTACK_TEST_RUNTIME_MANIFEST
DSTACK_TEST_CASE_MANIFEST
DSTACK_TEST_FIXTURE_LEASE_ID
DSTACK_TEST_WORKDIR
```

The script writes the same final `result.json`, artifact manifest, attachments,
and STEP/EVIDENCE markers used by Agent cases. Exit code represents executor
health, not product status. A nonzero exit with a valid final result remains a
usable result; no valid final result is INCOMPLETE/INFRA_ERROR.

Capture stdout/stderr as process JSONL events:

```jsonl
{"type":"process.started","pid":1234,"entrypoint":"shared/automation/run-test.py"}
{"type":"stdout","at":"...","text":"STEP ... START\n"}
{"type":"stderr","at":"...","text":"warning\n"}
{"type":"process.exited","exit_code":0,"duration_ms":1234}
```

Record executor type, entrypoint, args, SHA-256, session format, PID, timing, and
exit code in `runner.json`. Start scripts in their own process group. Timeout or
Stop sends SIGTERM, waits a bounded grace period, and then sends SIGKILL to the
verified group.

## 10. Agent executor

Retain current Codex/Claude behavior when no entrypoint is declared. Agent and
script modes share fixture provisioning, manifests, result validation,
evidence, attachments, checksum generation, collection, cleanup, UI, renderer,
and package validation.

Agent responsibilities are limited to testing product behavior and explaining
results. It must not discover general lab resources, allocate ports/CIDs,
construct generic fixtures, or provide final cleanup guarantees.

## 11. Evidence and report contracts

Keep one result schema for both executors. Every evidence or attachment record
must contain an owning `step_id` and a concrete description of what it proves.
Separate fixture events and initial-state checks from product test steps so
fixture success cannot be counted as product evidence.

Add fixture metadata to reports:

```json
{
  "fixture": {
    "profile": "storage-lifecycle",
    "lease_id": "...",
    "provider": "physical-tdx-vmm",
    "versions": {},
    "initial_state": {},
    "provision_status": "PASS",
    "cleanup_status": "PASS"
  }
}
```

Product PASS with failed cleanup must be visibly classified as an infrastructure
execution error; resource leakage must never be hidden.

## 12. Stop → Start dashboard bug

Observed defect:

- after Stop followed by Start, the controlled case executor ran;
- the overview continued displaying stale `orchestrator_status=PASS` from the
  old `run.json`/orchestrator session;
- overview stayed attached to `orchestrator.jsonl`, so new case output was not
  visible.

Required fix:

1. live controller state is authoritative whenever it is running;
2. return a `log_agent`/`execution_source` from the control/state API;
3. controlled execution reports orchestrator status RUNNING, not stale PASS;
4. overview switches to `case:<current_case>` while a controlled case runs;
5. when current case changes, reset log offset and rendered-chat state;
6. when stopped, show STOPPED/INCOMPLETE rather than stale PASS;
7. preserve access to historical orchestrator output through an explicit
   selector;
8. tests must reproduce Stop → Start → new case output and confirm status,
   source, offsets, and live updates.

## 13. UI changes

Rename Agent output to Execution output. Display executor type and, for scripts,
entrypoint and SHA-256. Add fixture panels for profile, lease, provisioning,
initial state, resources, collection, cleanup, and leaks. Add control actions:
Provision, Start, Stop, Destroy fixture, Retry provisioning, and rerun with a
new fixture.

Script process JSONL must render live and historically. Evidence and attachments
remain step-linked and independently collapsible.

## 14. Validation and tests

Add coverage for:

- agent case remains backward compatible;
- valid script PASS, product FAIL, and BLOCKED;
- script nonzero exit with valid result;
- missing/invalid/provisional result;
- entrypoint path/symlink escape and bad args;
- stdout/stderr streaming and STEP/EVIDENCE parsing;
- timeout and Stop kill the complete process group;
- no retry within a round; explicit Start retries with archive/new lease;
- fixture initial-state failure;
- cleanup after PASS, FAIL, timeout, Stop, and controller restart;
- lease reconciliation and exact ownership boundaries;
- Stop → Start status/log regression;
- dashboard script/fixture/evidence/attachment rendering;
- validator, offline HTML, ZIP package, SHA256SUMS, and attachment references.

## 15. Implementation phases

### Phase 1 — compatible foundation

- Extend plan parsing for execution/fixture/actions-under-test.
- Implement script executor and process JSONL.
- Generalize runner metadata from Agent to executor while accepting old files.
- Fix Stop → Start status and live-log selection.
- Add unit/integration tests and documentation.

### Phase 2 — leases and fixture lifecycle

- Implement provider interface, lease journal, case manifests, lifecycle states,
  cleanup reconciliation, and fixture/report/UI surfaces.
- Initially provide `noop`, `process`, and local simulator providers.

### Phase 3 — physical TDX host isolated providers

Implement `guest-lifecycle`, `no-tee-dev`, `storage-lifecycle`,
`container-observability`, and `network-lifecycle`. Never reuse the two current
long-lived development CVMs as mutable fixtures.

### Phase 4 — component and version providers

Support isolated VMM, KMS, Gateway, Verifier, local-key-provider, and simulator
processes plus pinned 0.5.4, 0.5.8, 0.5.11, and candidate artifact catalogs.
Implement mixed-version and KMS onboarding profiles.

### Phase 5 — hardware pools

Integrate TDX, SEV-SNP, GCP TDX, Nitro TPM/Enclave, and NVIDIA CC pools with
exclusive leases, health checks, TTL, and explicit hardware/simulation labels.

### Phase 6 — migrate all 361 cases

Assign every case a fixture classification and contract. Convert deterministic
RPC, CLI, configuration, boundary, build, and compatibility matrices to script
entrypoints. Retain Agent execution for exploratory, hardware-variable, and
root-cause-oriented cases. Validate source/requirement/config/API traceability
again after migration.

## 16. Acceptance gates before resuming physical TDX host

- all `test-suites/runner` tests pass;
- sample Agent and script plans both execute and render;
- Stop → Start regression is proven fixed in a live dashboard test;
- fixture Stop/crash cleanup is verified with no leaked process or resource;
- case manifest and lease checksums validate;
- existing historical Agent results still render and package;
- the same run ID can archive the interrupted attempt and resume without
  overwriting terminal results;
- physical-host reboot remains impossible through all providers.
