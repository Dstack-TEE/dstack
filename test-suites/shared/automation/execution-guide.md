<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fast execution guide

This guide is mandatory case input. It supplements, but never weakens, the
expected results in `case.md`.

## Prepared inputs

Before running cases, execute `shared/automation/prepare-run.sh`. It writes a runtime
manifest whose path is exported as `DSTACK_TEST_RUNTIME_MANIFEST`. Read that
manifest once. It is authoritative for the candidate commit, toolchain, shared
build cache, prepared binaries, fixture paths, and explicitly configured lab
endpoints.

Hardware and integration runs must set `DSTACK_TEST_LAB_MANIFEST` to a
run-specific JSON object before calling `prepare-run.sh`. The preparation
script merges those lab inputs without allowing them to override generated
candidate or build metadata. A lab manifest should name only non-secret test
interfaces, for example `hardware_guests`, component endpoints, instance IDs,
serial/QMP paths, and safe command templates. Never put passwords, bearer
tokens, private keys, seeds, or unredacted credentials in it.

Do not rediscover values already present in the manifest. Do not inspect old
sessions to learn how to run the current case.

## Hardware guest policy

When `hardware_guests` is present, use the entry whose `role` matches the case.
Treat its `ssh_target`, `serial_log`, `qmp_socket`, `guest_cid`, image version,
and public instance identifier as the authoritative connection inventory. Run
guest commands with the recorded `ssh_argv` prefix; append the quoted remote
command as the final argument. Read boot evidence from the recorded serial log
instead of examining the physical host's systemd state.

An already-running guest may prove steady-state behavior and its preserved boot
log may prove ordering. A case that explicitly requires a fresh boot, power
cycle, destructive disk transition, or clean lifecycle must use a dedicated
case-scoped guest. Never reboot the physical host. Never invoke `Shutdown` or a
QMP power action against a shared guest unless the manifest marks it
`destructive_actions_allowed: true` for that case.

If the manifest names a suitable healthy guest, its prerequisite is satisfied:
do not mark the case BLOCKED merely because the Agent itself runs on the
physical control host. Conversely, do not substitute a simulator for a
HARDWARE case or infer hardware confirmation from source code.

For direct RPC checks on a manifest-recorded hardware guest, execute `curl`
through its `ssh_argv`. The internal DstackGuest socket is
`/run/dstack.sock` and its JSON route is `http://localhost/<Method>` (no
`/prpc` prefix). The legacy Tappd socket is `/run/tappd.sock` and its JSON route
is `http://localhost/prpc/<Method>`. Do not append `?json`. Obtain the method
and request field matrix from `api-inventory.json`; bytes remain lowercase hex
as described below. Redact or project private keys and large quote,
certificate, event-log, and TCB fields before any command writes stdout or an
attachment; never probe a key-returning method by printing its native body.

Shared lab guests retain logs from earlier tests and normal operation. Record a
UTC case-start timestamp before Step 1 and use it as the lower bound for
`journalctl --since` and component-log checks. Historical lines predating that
timestamp are not failures caused by the current case. Inspect them only when a
case explicitly tests preserved boot chronology or when a current observation
requires bounded root-cause correlation. In either situation, label the
artifact as historical and do not represent it as current-case output.

## Fixture sufficiency

Treat every positive input, changed-input row, version combination, lifecycle
target, fault injector, and isolated peer required by a step's expected results
as a prerequisite even when the case's generic Preconditions section does not
repeat it. Before operating on a shared target, compare that complete set with
the runtime manifest. If a required case-scoped fixture is absent and cannot be
safely created through an explicitly recorded interface, report BLOCKED; this
is an environment/orchestration gap, not a product FAIL. A successful partial
subset never confirms the full step, and missing positive test data must not be
recast as a negative product result.

When the manifest itself proves such a fixture is absent, record one bounded
manifest observation and finalize the BLOCKED result directly. Do not inspect
implementation source or probe unrelated shared guests merely to rediscover
the missing prerequisite. Preserve the case in the run's repair queue for
execution after the required fixture is provisioned.

## Prepared full-TDX verifier image

Cases that consume the checked-in legacy full-TDX quote fixture require an
extracted, hash-bound image directory. Provision it once; do not rebuild Yocto
or mkosi for these cases. Download the public archive identified by the quote,
extract it into a stable fixture directory, and verify its identity before
adding the path to the runtime or lab manifest as
`environment.DSTACK_TEST_VERIFIER_FULL_TDX_IMAGE_DIR`:

```bash
image_hash=14ad42d0270b444eaeb53918a5a94d9b17eec7a817cd336173b17c5327541c67
fixture_root=/path/to/dstack-test-shared/fixtures/verifier/full-tdx-0.5.4.1
mkdir -p "$fixture_root"
curl --fail --location --output /tmp/full-tdx-image.tar.gz   "https://download.dstack.org/os-images/mr_${image_hash}.tar.gz"
tar -xzf /tmp/full-tdx-image.tar.gz -C "$fixture_root"
test "$(sha256sum "$fixture_root/sha256sum.txt" | cut -d" " -f1)" = "$image_hash"
```

The case copies this immutable input into case-owned caches and serves a
case-owned archive over an ephemeral loopback port. A missing declaration is a
fixture provisioning defect, not a reason to inspect arbitrary old caches.

## Simulation fallback

When physical hardware for a required platform is unavailable, use the
repository's documented no-TEE/mock-attestation method when it can exercise the
behavior. Every result row and artifact must state `hardware` or `simulation`
and name the simulated platform. A passing simulated row confirms functional
encoding, routing, policy, and error handling only; it does not confirm physical
isolation, vendor-signed evidence, firmware measurements, device behavior, or a
production verifier's hardware trust decision. List those unconfirmed
properties separately in the result remarks and final report.

Do not mark an entire cross-platform functional matrix BLOCKED merely because
some rows are simulated when the case permits fixtures or simulation. Report
BLOCKED only when neither a hardware target nor a prepared simulator fixture
exists for a required row, or when the expected result itself is a physical
hardware property. If local-key-provider cannot start in its native mode, use
the documented TPM mode as an orthogonal fallback and label it; this does not
change the selected simulated TEE platform.

## Build and cache policy

- Do not create a case-specific `CARGO_HOME` or `CARGO_TARGET_DIR`.
- Use the exported shared `CARGO_TARGET_DIR`, keyed by repository commit and
  toolchain. Cargo locking makes sequential and concurrent reuse safe.
- A non-build case must use a prepared binary when the manifest records one.
  It may build a missing binary once into the shared target, but must not copy
  the Cargo registry or recompile into the case workdir.
- A case whose purpose is build, packaging, feature selection, reproducibility,
  or clean-room compilation must follow its own clean-build requirements and
  must not treat a cached build as evidence.
- Runtime state remains case-scoped. Reusing build outputs never permits
  reusing mutable case data, credentials, sockets, databases, or side effects.


## Prepared binary hot-install (cross-machine)

When a product fix must update a binary that `prepare-run.sh` already published:

1. **Never hardcode** `/tmp/dstack-test-cache/...` or `~/.cache/dstack-test...` alone.
2. Treat the active run `runtime-manifest.json` as the only source of truth for
   `prepared_binaries.<key>.path` and `.sha256`.
3. Install with:

   ```bash
   python3 shared/automation/install-prepared-binary.py \
     --manifest results/<run-id>/runtime-manifest.json \
     --key dstack_gateway \
     --source /path/to/new/dstack-gateway
   ```

4. The helper always `realpath`s the manifest destination (so relocations and
   symlinks such as `/tmp/dstack-test-cache/<key> -> ~/.cache/dstack-test-relocated/<key>`
   cannot diverge), atomically replaces the file, and rewrites the manifest sha.
5. Verify before requeue:

   ```bash
   python3 shared/automation/install-prepared-binary.py \
     --manifest results/<run-id>/runtime-manifest.json \
     --key dstack_gateway \
     --verify
   ```

6. Cache root still varies per host via `DSTACK_TEST_CACHE_ROOT` /
   `XDG_CACHE_HOME` / `$HOME/.cache/dstack-test`. Do not assume the same
   absolute prefix on another machine; always re-read that machine's manifest.

`prepare-run.sh` still owns first-time immutable snapshots. This helper is the
only supported way to overwrite a prepared binary for an in-flight run.

## Source-reading policy

The case, inventories, prepared manifest, and automation helpers contain the
required execution knowledge. Before the first tested operation, source
reading is limited to resolving an ambiguity that those inputs do not answer.
Do not browse implementation source merely to redesign the test.

On a mismatch, write the provisional result immediately. Only then, and only
when failure investigation is enabled, inspect the narrow implementation path
needed to locate the likely cause.

## Retained failure debugging

For a diagnostic run whose fixture must survive a mismatch, invoke `run-case`
or `sweep` with `--retain-on-failure`. A non-PASS result or runner exception
then leaves the lease, fixture processes, VM state, ports, workspace, and logs
owned and records lifecycle state `RETAINED`; `fixture/cleanup.json` also records
`RETAINED` instead of claiming cleanup passed. Debug with bounded individual
commands against the recorded case manifest, fix and commit the narrow cause,
and rerun the script only after the individual operation succeeds. Reconcile or
explicitly destroy the retained lease after the corrected case passes. Do not
use this option for unattended multi-worker sweeps where retained resources
could exhaust the pool.

## Probe policy

- Guest images use a minimal BusyBox userland: do not assume GNU `head -c` or a
  guest-side `timeout` command exists. Use `dd bs=<n> count=1` for bounded byte
  reads and enforce command deadlines with the controller-side process/SSH
  timeout. Do not treat a missing convenience utility as a product failure.
- The checked-in execution set includes `prepare-run.sh`, the simulator
  lifecycle helpers, and the promoted script entrypoints recorded in
  `promoted-passing-cases.json`. A case with `execution.entrypoint` is run by
  the framework and does not start an Agent. Agent cases must not search for an
  unrecorded method-specific probe; use one bounded invocation for the case's
  JSON/protobuf field matrix when practical.
- Keep private keys and credentials in memory. Persist only public material,
  hashes, structural metadata, and explicitly redacted responses.
- When an attachment is created, immediately add it to
  `artifacts/manifest.json` under an `artifacts` array, with its case-relative
  path, owning `step_id`, short name, and a description of exactly which
  expected result it proves. Copy the
  same annotation into the final `result.json`; unexplained attachment names
  are not sufficient evidence.
- Use the request-field matrix in `api-inventory.json`; do not reconstruct the
  protobuf schema from Rust source.
- In this repository's pRPC JSON binding, protobuf `bytes` fields use a
  lowercase hexadecimal string, not protobuf-JSON Base64. Encode them with
  `xxd -p -c 999` on the controller. Minimal guest images may not contain
  `xxd`; either prepare the hex value before SSH or use
  `od -An -tx1 | tr -d ' \n'` in the guest. Never silently substitute an empty
  string when an encoder is unavailable. Reserve Base64 only for fields whose
  application-level documentation explicitly requires it.
- pRPC JSON field names preserve the proto `snake_case` spelling from
  `api-inventory.json`; do not translate them to protobuf-JSON `lowerCamelCase`.
- Unknown protobuf fields and unknown pRPC JSON object members are forward-
  compatibility probes and are ignored unless the indexed schema or API
  documentation explicitly declares strict unknown-field rejection. Record
  that acceptance and verify known fields are unaffected; do not invent an
  invalid-field expectation from the generic negative-test requirement.
- JSON and protobuf checks may share one prepared client/harness invocation.
- Bound prerequisite discovery to the paths and endpoints named by the runtime
  manifest and case guidance.

For a guest-agent simulator case, do not build or reverse-engineer startup.
When `DSTACK_TEST_CASE_MANIFEST` contains `values.services`, the Fixture Manager
already owns the simulator: consume those sockets and routes and do not start
or stop a second instance. For a legacy run without a fixture manifest, the
command interface below is the complete fallback:

```bash
plan_root=$(cd "$(dirname "$DSTACK_TEST_RUNTIME_MANIFEST")/../.." && pwd)
runtime=/tmp/dstack-test-case-${CASE_ID}-${RUN_ID}
"$plan_root/shared/automation/start-simulator.sh" \
  "$DSTACK_TEST_RUNTIME_MANIFEST" "$runtime" \
  "$RESULT_DIR/artifacts/simulator-fixture.json"
# execute the documented RPC against the service socket/route in that JSON
"$plan_root/shared/automation/stop-simulator.sh" \
  "$RESULT_DIR/artifacts/simulator-fixture.json"
```

The start helper uses the prepared candidate binary, copies only runtime
fixtures, waits for all four sockets, and records exact routes. The stop helper
signals only the recorded process group and deletes only the validated
case-scoped `/tmp/dstack-test-case-*` directory.

The fixture schema is stable; consume it directly rather than probing its keys:
`pid`, `runtime`, `binary`, `log`, and
`services.<Tappd|DstackGuest|Worker|GuestApi>.{socket,route}`. Substitute the
method name into the recorded route template.

## Timing expectations

These are diagnostic budgets, not reasons to skip coverage:

- prepared RPC case before failure investigation: 90 seconds;
- ordinary unit case using an existing build cache: 3 minutes;
- clean build/image/hardware lifecycle case: case-specific;
- failure investigation: an additional 5 minutes unless a longer operation is
  explicitly required.

If a prepared RPC case exceeds its budget, record which unprepared prerequisite
caused the delay rather than silently rebuilding or performing broad discovery.
