<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="core-fixture-profiles"></a>
# Core plan fixture profiles

`profiles.json` is the authoritative profile registry for this plan. Every
indexed case declares one profile, its component-version request, whether real
hardware is required, whether simulation is permitted, and the product actions
that fixture setup must not perform.

Profiles describe an initial state, not a successful product transition. A
provider may allocate substrate, start dependencies, and establish the declared
initial state. It must not perform a case's `actions_under_test` and later use
fixture output as product evidence.

Provider names have these meanings:

- `local-simulator`: the checked simulator helper lifecycle, scoped by lease;
- `tdxlab-isolated`: a lab adapter that creates a new case-owned guest;
- `isolated-component`: a case-owned component process and data directory;
- `version-matrix`: pinned 0.5.4, 0.5.8, 0.5.11, and candidate components;
- `hardware-pool`: an exclusive allocation with TTL and explicit labeling.

The four non-local providers use the external provider command protocol. The
controller reads only an executable path from the matching environment
variable, for example `DSTACK_TEST_PROVIDER_TDXLAB_ISOLATED`. It invokes that
file with `prepare`, `verify`, and `destroy`; requests and responses are JSON
objects. Shell fragments are not accepted. Missing providers produce a bounded
`BLOCKED` result without starting an Agent or script.

Run the contract audit after changing the index or registry:

```bash
python3 fixtures/validate-contracts.py .
```

## tdxlab isolated guest adapter

The checked adapter at `fixtures/providers/tdxlab-isolated.py` creates a new
lease-owned candidate CVM, waits for guest boot and SSH-over-gateway readiness,
publishes the case-scoped SSH and RPC inventory, and removes the VM during
fixture cleanup. It never restarts the physical host and never selects an
existing VM. Prepare a complete tdxlab run with the checked preflight wrapper:

```bash
plan=$PWD/docs/test-plans/core-components-full
run_id=<run-id>
"$plan/automation/prepare-tdxlab-run.sh" \
  "$PWD" "$plan/results/$run_id/runtime-manifest.json"
```

The wrapper validates and prepares the pinned Foundry toolchain, KMS JavaScript
dependencies and contract submodules, full-TDX verifier fixture, container base
image, and all external provider paths. It records those non-secret inputs in
the runtime manifest so case execution does not depend on the launching shell
retaining exports.

Run the scripted suite through the checked tdxlab wrapper:

```bash
"$plan/automation/run-tdxlab-sweep.sh" \
  "$PWD" "$run_id" "$plan/results/$run_id/runtime-manifest.json" 4
```

The wrapper serializes a small substrate-sensitive preflight before starting
the parallel round. A preflight failure stops the round, while successful
preflight cases are not repeated. Every sweep also audits its lease journal;
an unexpected non-released lease or resource is reported as a `<postflight>`
infrastructure failure. `--retain-on-failure` remains an explicit exception for
interactive debugging and retained leases must later be reconciled normally.

For provider development without the wrapper, configure it explicitly before
starting the controller:

```bash
export DSTACK_TEST_PROVIDER_TDXLAB_ISOLATED="$PWD/fixtures/providers/tdxlab-isolated.py"
export DSTACK_TEST_SSH_GITHUB_USER=kvinwang
export DSTACK_TEST_VMM_URL=http://127.0.0.1:12000
export DSTACK_TEST_GUEST_IMAGE=dstack-0.6.0
export DSTACK_TEST_IMAGE_STORE=/var/lib/dstack-test/candidate-images
```

`DSTACK_TEST_SSH_GITHUB_USER` must identify the test operator whose public SSH
keys are installed by the lab's development-image bootstrap. Optional
`DSTACK_TEST_GATEWAY_DOMAIN` and `DSTACK_TEST_GATEWAY_PORT` override
`tdxlab.dstack.org:13004`. The provider stores no private key or bearer token in
the fixture manifest.

`DSTACK_TEST_IMAGE_STORE` is mandatory for image-assembly cases. It must point
to a protected, operator-owned candidate image directory outside case fixture
workspaces and source checkouts. Fixture cleanup never owns or removes this
directory.
