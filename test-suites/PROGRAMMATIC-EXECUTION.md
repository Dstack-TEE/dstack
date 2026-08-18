# Programmatic execution of this test plan

This plan used to be driven by an LLM orchestrator that decided, case by case,
what to run. Measured over run `central-fixtures-20260724T032131Z` that cost
43 of 72 wall-clock hours in orchestrator stalls and per-decision turns, at a
maximum concurrency of one. The loop is now deterministic and the AI is out of
the execution path.

## Running the plan

```sh
# Deterministic driver (default). Replaces the LLM orchestrator with the loop
# it was already constrained to: next-case, then run-case or complete-case.
test-suites/runner/dstack-test run-plan --plan <plan> --driver program

# Fast regression over every case that owns a checked-in harness.
test-suites/runner/dstack-test sweep --plan <plan> --run-id <id> --workers 8 \
  --runtime-manifest <run>/runtime-manifest.json

# Registry integrity: every promoted case must be backed by a harness that
# actually handles it.
test-suites/runner/dstack-test verify-registry --plan <plan>
```

On tdxlab, create the runtime manifest with
`shared/automation/prepare-tdxlab-run.sh` rather than calling `prepare-run.sh`
directly. The wrapper makes every external provider and deterministic tool/data
prerequisite part of the prepared run; plain preparation cannot provision those
lab-specific inputs.

A scripted case averages 0.4s against 178s for an agent-driven one, so the
whole scripted set sweeps in seconds. That is what makes "fix, then re-verify"
cheap enough to do on every change.

## The rule that matters

A case is only scripted when its harness reproduces what the case claims to
test. Two mechanisms enforce this, both added after the registry was found
asserting things that were not true:

- `verify-registry` rejects a promotion whose harness does not handle the case.
  It caught nine cases registered against `passed-rpc-case.py` whose table
  never listed them; every rerun had been dying with `KeyError` while the
  registry reported them as deterministic passes.
- `shared/automation/mine-passing-attempt.py` refuses to emit a spec when it cannot
  template every recorded operation. Under the earlier permissive rule, five of
  eight verified specs were replaying only part of their recorded operations.

Prefer an honest `BLOCKED` or an unregistered case over a harness that passes
without exercising the behaviour.

## Adding a harness

Most cases fall into a family that already has a table-driven harness in
`shared/automation/`. Extending a table is cheaper and more reviewable than writing a
new script:

| family | harness |
| --- | --- |
| guest-agent simulator RPC | `passed-rpc-case.py` |
| VMM RPC | `passed-vmm-empty-rpc-case.py` |
| gateway RPC | `passed-gateway-empty-rpc-case.py` |
| gateway ZT domains | `passed-gateway-zt-domain-case.py` |
| KMS RPC | `passed-kms-rpc-case.py` |
| replay of a mined attempt | `replay-case.py` + `shared/automation/replay/<case>.json` |

A harness reads `DSTACK_TEST_CASE_MANIFEST` for its lease-owned fixture, prints
`STEP`/`EVIDENCE` markers, and writes `result.json` plus artifacts. Never hard-code
a port, a workspace path, or the candidate repository: they differ per lease.

### Contract limits to respect

The RPC harnesses call each method over JSON, then protobuf, then once more,
and require every call to succeed. That fits idempotent methods only.
`Vmm.RemoveVm` is not idempotent; `Vmm.ShutdownVm`, `Vmm.SvStop` and
`Vmm.SvRemove` need a running guest and supervisor process that the prepared
stopped VM does not have. Those need a harness that models a state transition
rather than repeating one call.

Do not assert determinism without checking. `Vmm.GetAppEnvEncryptPubKey`
returns a timestamp and signatures over it, so two identical requests match
byte for byte only within the same second: it passes alone and fails under a
parallel sweep.

## Substrate settings belong to the run

Fixture providers read lab-specific locations from the environment. Declare
them in `manifests/tdxlab.json`, which `prepare-run.sh` merges into
`runtime-manifest.json`; `run-case` exports them before provisioning. A missing
variable used to surface as a fixture `INFRA_ERROR` indistinguishable from a
real capability gap — 60 `BLOCKED` and 15 `INFRA_ERROR` results in one sweep
were nothing but an unset variable.

Use `environment` for plain values and `environment_path_prepend` for toolchain
directories, since `PATH` is always set and cannot use the set-when-unset rule.

## Script coverage

The suite currently contains 358 cases. Distributed case metadata declares a
checked-in execution entrypoint for 357 of them. The remaining macvtap
connectivity case is agent-driven until it has a reproducible harness.

## Known substrate defect

`tdxlab-isolated` targets an external shared VMM through `DSTACK_TEST_VMM_URL`,
default `127.0.0.1:12000`. That instance runs from a deleted working directory,
so `CreateVm` fails with "Failed to load image" and every hardware case errors.
The provider should own a per-lease VMM the way `isolated-component` does.

When copying that provider's VMM startup, note that it passes a
`simulator_seed` unconditionally, which appends a `[cvm.tee_simulator]` block
and yields software-simulated quotes. A provider that exists to produce real
hardware quotes must pass an empty seed.

## The 86 BLOCKED/SKIPPED results are not a finished category

Run `central-fixtures-20260724T032131Z` left 86 cases BLOCKED or SKIPPED. It is
tempting to read those as settled — a capability the lab does not have. Reading
every summary shows otherwise. They almost all say some variant of *the fixture
did not provide this*:

- "the fixture lacks the case-scoped local PCCS/key-provider lifecycle"
- "the prepared no-tee-dev simulator fixture lacks the required case-owned TPM
  simulator/proxy endpoint"
- "the gateway cluster was healthy, but the fixture lacked the ACME/DNS
  issuance path"
- "the case-owned fixture declares no cryptographically verifiable attested
  client"
- "the image-assembly fixture provides no documented audit invocation
  parameters"

That is unprovisioned fixture work, not an unavailable capability, so those
cases do not qualify for a capability-based BLOCKED. Only nine mention
something the host genuinely may not offer — GPU, SEV-SNP, or hugepages:

    tc-gos-attestatio-006  tc-gos-gpupolicy-007   tc-gos-platform-009
    tc-gos-setup-011       tc-gos-yocto-006       tc-kms-release-010
    tc-ver-input-plat-005  tc-vmm-compute-ne-003  tc-vmm-compute-ne-004

and even those need a probe that demonstrates the absence rather than an
assertion that it is absent.

The practical consequence: the remaining work is not only the 241 behavioural
harnesses. It also includes provisioning the capabilities those fixtures are
missing — a local PCCS, a TPM/vTPM proxy, an ACME/DNS issuance path, attested
KMS clients, image-assembly audit handles. Budget for that before treating the
BLOCKED column as closed.

### Host capability on tdxlab

tdxlab does have working TDX. An earlier probe recorded here checked the host
for `/dev/tdx_guest` and concluded otherwise; that is a guest-side device node
and was the wrong thing to look for. What settles it is that
`/sys/firmware/acpi/tables/CCEL`, the TDX measured-boot event log, is readable
inside a provisioned guest.

Every hardware case that had been failing turned out to fail for a software
reason: a shared VMM running from a deleted directory, overlapping loopback
port blocks, and a harness reading guest identity from a path this release does
not use. All of them now pass. Do not record a case as capability-blocked
without a probe that demonstrates the absence.

## Measured host capability on tdxlab

Probed directly on the lab host, so a capability probe has something concrete
to assert rather than restating a case summary:

| capability | probe | result |
| --- | --- | --- |
| TDX guest device | `/dev/tdx_guest` | absent |
| SEV guest device | `/dev/sev-guest`, `/dev/sev` | absent |
| SEV CPU support | `grep -c sev /proc/cpuinfo` | 0 |
| 2 MiB hugepages | `/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages` | 0 |
| NVIDIA GPU | `nvidia-smi -L` | command not found |

Each of the nine hardware-citing cases should run a harness that performs the
matching probe, records the observation as evidence, and finalises BLOCKED on
that basis. A probe that finds the capability present must fail rather than
pass, so the case stops being BLOCKED the moment the lab gains the hardware.

## Next: a failed guest boot preserves nothing

tc-gos-setup-004 is the one case still not passing, and it is intermittent: it
passes on its own and fails inside a full sweep with

    tdxlab-isolated provider prepare failed with 1:
    VM did not enter running state: exited

The guest starts and then exits. Why is currently undiagnosable, because
`tdxlab-isolated` removes the lease workspace when provisioning fails, taking
the guest serial and console output with it. Nothing under `results/<run>/`
retains them.

Fix that first: on a provisioning failure, copy the guest serial log and the
VMM log into the case result directory before tearing the workspace down. Every
later attempt to explain this class of failure needs those two files, and no
amount of rerunning produces them.

Note this is a fixture-stability problem, not a determinism one. The same case
passed at `--workers 1`, so suspect resource contention during concurrent guest
startup even though hardware cases are already serialised against each other —
the software cases still run alongside them.

## Resolved: guests exited early when started concurrently

Three cases passed at one worker and failed in a concurrent sweep, the guest
exiting about nine seconds in with no console output and no instance id.

The cause was loopback port allocation. `find_port_block` bound each candidate
port to test it, closed the socket and returned the base, so concurrent leases
scanning from the same start received overlapping blocks: 19026-19029,
19027-19030 and 19028-19031 all claimed port 19028. qemu then refused to start
with `Could not set up host forwarding rule 'tcp:127.0.0.1:19028-:22'`.

Ports are now reserved with an `O_EXCL` marker per port, claimed for the whole
block and rolled back if any port is taken. All 93 cases pass at eight workers
across three consecutive runs, and the sweep dropped from about 282 seconds
under the interim serialisation workaround to about 88.

Two things made this take far longer than it should have.

- **The diagnostic chain had three broken links.** The guest serial log is
  fetched through the VMM after the guest is gone, so it always came back
  empty; the VMM log records only that the guest exited; and the failure
  message is truncated by the lifecycle record. The reason lives in qemu's own
  `stderr.log` under the VMM run path, outside the lease workspace that
  teardown deletes. Failures now preserve the whole log directory and VM run
  directory to `/tmp/dstack-test-failed-leases`.
- **Serialising the guest cases hid it.** That made the suite green while
  leaving the defect in place and costing 110 seconds a run. Reach for the
  evidence before reaching for the workaround.

One related defect is still open: `isolated-component` computes
`cid_start = 100_000 + rpc_port * 4` against a 1000-wide CID pool, so two of
its leases whose rpc ports differ by less than 250 receive overlapping guest
CID ranges. `tdxlab-isolated` strides by 1000 and is correct.

## What "no AI in the execution loop" does and does not mean today

The orchestrator is gone: `run-plan --driver=program` decides what to run in
process, and `sweep` re-runs the scripted set with no model involved at all.
That is the path used for every result quoted here.

It does not yet mean the whole plan runs without a model. `run_case` dispatches
on whether the case owns an entrypoint (test-suites/runner/dstack-test, around
line 1126):

    if case.execution is not None:
        value = run_script_case(...)
    else:
        value = run_agent_case(...)

So running the full plan today spawns an agent only for the single case without
an execution entrypoint. The other 357 cases execute deterministically.

Two consequences worth keeping in mind:

- Quote the scripted count alongside any "programmatic" claim. "356 of 358 cases
  run deterministically" is true; "the entire plan runs without AI" is not yet.
- `run-plan --driver=program --require-script` refuses the first case without
  an entrypoint instead of falling back, which makes the boundary enforceable
  rather than conventional. It currently halts at `tc-vmm-compute-ne-009`
  instead of spawning an agent.
