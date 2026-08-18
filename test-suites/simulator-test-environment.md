<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Simulator-backed attestation test environment

This environment exercises production attestation encoders, guest ABIs, parsers, routing, verification policy, and failure handling with development-only trust material. It does not make a physical hardware trust claim.

## Topology

The checked-in suite is `dstack/tests/e2e/attestation/`. Docker Compose builds one immutable test image and starts one disposable privileged container per row:

| Compose service | Attestation mode | Guest ABI |
|---|---|---|
| `dstack-tdx-legacy` | TDX legacy | ConfigFS TSM |
| `dstack-tdx-lite` | TDX lite | ConfigFS TSM |
| `gcp-tdx` | GCP TDX/vTPM | ConfigFS TSM and vTPM |
| `amd-sev-snp` | AMD SEV-SNP | ConfigFS TSM |
| `aws-nitro-enclave` | AWS Nitro Enclave | NSM CUSE device |
| `aws-nitro-tpm` | AWS NitroTPM | vTPM and NSM evidence |

Inside each container, `dstack-tee-simulator` exposes the platform ABI. `dstack-util attest` obtains versioned evidence, and `dstack-verifier` verifies it using production-shaped collateral served by `dstack-mock-attestation`.

## Trust and policy model

`dstack-mock-attestation` derives non-production certificate hierarchies from the case seed. The collateral service exposes only public PCCS, AMD KDS, TPM AIA/CRL, and NSM certificate material; it exposes no signing endpoint.

Development verification requires both custom roots and:

```toml
[attestation]
insecure_allow_external_trust_anchors = true
```

Every accepted result must contain:

```json
{"details":{"simulated":true}}
```

The same evidence and roots must be rejected when the explicit opt-in is removed. A custom root alone must never silently turn production policy into development policy.

## Host prerequisites

- Linux with Docker Compose, loadable modules from `/lib/modules`, and permission to run privileged containers.
- `jq`, `xxd`, `sha256sum`, `mount`, and `modprobe` in the test image.
- The candidate checkout and prepared Rust build cache.
- Place Cargo targets and Docker build caches on a filesystem with verified free space; do not use a full root-backed `/tmp` volume.
- No production credentials. Seeds, private development keys, device nodes, mounts, and work files remain inside disposable containers.

On managed hosts, launch every Docker command through the `kvin` identity:

```console
sudo su kvin -c "docker ..."
```

## Running the suite

From the candidate checkout:

```console
cd dstack/tests/e2e/attestation
sudo su kvin -c "docker compose build"
for service in dstack-tdx-legacy dstack-tdx-lite gcp-tdx amd-sev-snp aws-nitro-enclave aws-nitro-tpm; do
  sudo su kvin -c "docker compose run --rm $service"
done
sudo su kvin -c "docker compose down --remove-orphans"
```

Run the promoted case through the plan runner rather than invoking its Python harness directly. The harness writes one log per platform plus `platform-policy-matrix.json` under the run's case artifact directory.

## Preparing a candidate mkosi guest image

Image-backed guest cases must not reuse an older image merely because it has the same release version. Build from a clean worktree at the candidate commit so the embedded binaries and recorded revision agree:

```console
mkdir -p "$HOME/.cache/dstack-test/tmp/mkosi"
export TMPDIR="$HOME/.cache/dstack-test/tmp/mkosi"
./os/mkosi/build.sh lint
FLAVORS=dev DSTACK_DEV_CACHE_DIR="$HOME/.cache/dstack/mkosi-dev" \
  ./os/mkosi/build.sh dev-image "$HOME/.cache/dstack-test/mkosi-candidate-<commit>"
```

`mkosi` uses temporary image and component-build storage in addition to its
final output directory. Set `TMPDIR` explicitly to a filesystem with enough
space; relocating only the output directory does not prevent a full
root-backed `/var/tmp` from aborting the build.

Use `FLAVORS=dev` for SSH-based Guest OS cases; `FLAVORS=prod` intentionally disables development access and is only suitable for production-image checks. For a package-boundary comparison, build both flavors from the same clean revision and output root:

```console
TMPDIR="$HOME/.cache/dstack-test/tmp/mkosi" FLAVORS="prod dev" JOBS="$(nproc)" \
  ./os/mkosi/build.sh image "$HOME/.cache/dstack-test/mkosi-boundary-<commit>"
```

Verify both generated `out/{prod,dev}/dstack-<version>/sha256sum.txt` files and
the matching `metadata.json.git_revision` values. Install each complete
directory in the configured image store under a unique immutable name; do not
overwrite a shared release image in place. Select a boot image in the
host-specific lab manifest with `environment.DSTACK_TEST_GUEST_IMAGE`;
`prepare-run.sh` carries that selection into the runtime manifest used by
fixture providers. Boundary cases additionally name the immutable inputs with
`DSTACK_TEST_GUEST_PROD_IMAGE` and `DSTACK_TEST_GUEST_DEV_IMAGE`. Keep the
build directory, component cache, output root, and `TMPDIR` on a filesystem
with verified free space.

The mkosi formatter emits the same VMM image-directory contract as the release backend, but that format compatibility does not change its provenance: result artifacts must identify the backend as mkosi and retain the candidate revision.

## Simulator versus VM image coverage

Use this Docker environment for evidence encoding, report-data binding, parsing, platform routing, trust-root opt-in, policy rejection, mutation handling, and verifier/KMS authorization fixtures. Use a candidate VM plus the current development OS image for boot, guest-agent RPC, real device behavior, image-contained certificate validity checks, storage, networking, VMM placement, and service lifecycle.

Simulator PASS does not confirm vendor production signatures, firmware/device measurements, physical isolation, confidential GPU behavior, NUMA placement, or hugepage placement. Results must label those limits rather than presenting simulation as hardware evidence.

## Cleanup and diagnostics

Each row traps process and mount cleanup. The outer harness always runs `docker compose down --remove-orphans`, including after a failed row. Preserve bounded component logs and public-root metadata, but never copy development private keys into result artifacts. After a run, verify that no run-owned container, simulator, collateral server, mount, lease, or reserved listener remains.

## Prepared mkosi and simulator runtime on constrained hosts

Prepare the candidate runtime from the clean runtime worktree. The immutable
snapshot includes both `dstack-simulator` (guest-agent RPC simulator) and
`dstack-tee-simulator` (Linux TEE ABI simulator):

```console
export DSTACK_TEST_LAB_MANIFEST="$PWD/test-suites/manifests/tdxlab.json"
export TMPDIR="$HOME/.cache/dstack-test/tmp"
test-suites/shared/automation/prepare-run.sh \
  "$PWD" "$HOME/.cache/dstack-test/runtime-<commit>.json" \
  "$HOME/.cache/dstack-test"
```

Verify that `candidate_commit` is the clean worktree HEAD,
`prepared_binaries.dstack_tee_simulator` names an executable immutable file,
and both `environment.DSTACK_TEST_GUEST_IMAGE` and
`environment.DSTACK_TEST_NO_TEE_GUEST_IMAGE` name mkosi images. The latter must
have `backend: mkosi` and `is_dev: true` in `metadata.json` when a case needs
SSH access or installs the current-HEAD binary into the guest.

The Compose commands below are only an auxiliary, containerized platform
check. They do **not** boot or validate the mkosi image and must not be cited as
mkosi Guest OS evidence. A Guest OS lifecycle case must acquire a
`tdxlab-isolated` lease, boot the fixture-declared mkosi image with VMM, and run
its operations through the recorded `ssh_argv`.

On a host whose root-backed `/tmp` lacks space, put Compose metadata on the
home volume. The assignment must be inside `su -c`, because `su` can reset the
outer environment:

```console
sudo su kvin -c "mkdir -p /home/kvin/.cache/dstack-test/docker-tmp && \
  export TMPDIR=/home/kvin/.cache/dstack-test/docker-tmp && docker compose build"
sudo su kvin -c "export TMPDIR=/home/kvin/.cache/dstack-test/docker-tmp && \
  docker compose run --rm dstack-tdx-legacy"
sudo su kvin -c "export TMPDIR=/home/kvin/.cache/dstack-test/docker-tmp && \
  docker compose down --remove-orphans"
```
