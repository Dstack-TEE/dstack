<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# dstack full-stack compose E2E suite

This directory contains a Docker Compose based test suite that mirrors the
`tdxlab`/`dstack-k8s deploy/compose` shape: host-side services run as normal
processes/containers, and QEMU is used only for the real app CVM under test.

```text
docker compose
  ├─ mock-cf-dns-api        # tiny Cloudflare API + TXT DNS mock
  ├─ pebble                 # ACME test server (HTTP-capable custom Pebble image)
  ├─ aesmd + local-keyprovider
  ├─ dstack-auth            # KMS auth webhook backed by auth-allowlist.json
  ├─ dstack-kms             # host-side dev KMS, not a CVM
  ├─ dstack-gateway         # host-side dev Gateway, not a CVM
  ├─ dstack-vmm             # launches real TDX/SNP app CVMs via QEMU
  └─ runner
       ├─ configures Gateway certbot to use mock CF + Pebble
       ├─ deploys legacy and lite TDX nginx CVMs
       ├─ verifies KMS key provisioning and HTTPS Gateway -> app routing
       └─ snapshots durable KMS/Gateway state for upgrade assertions
```

It is intended for a **real TDX/SGX host** (or SEV-SNP host after setting the
platform/image knobs). It is not a pure unit-test environment; QEMU still starts
a confidential VM for the app.

## Prerequisites

1. From this directory, build the host binaries from the dstack checkout:

   ```bash
   cargo build --release \
     --manifest-path ../../dstack/Cargo.toml \
     -p dstack-cli -p dstack-auth -p dstack-vmm -p dstack-kms \
     -p dstack-gateway -p supervisor
   ```

2. Make sure the host has the required devices/services:

   - `/dev/kvm`
   - Intel TDX support and QGS for TDX (`DSTACK_E2E_QGS_PORT`, default `4050`)
   - `/dev/sgx_enclave` and `/dev/sgx_provision` for the local key provider
   - an SGX QCNL config that works on the host. By default the suite uses
     `../../dstack/key-provider-build/sgx_default_qcnl.conf`; on hosts with a local
     PCCS, set `DSTACK_E2E_QCNL_CONF=/etc/sgx_default_qcnl.conf`.
   - `/dev/vhost-vsock` for guest↔host vsock services
   - a TDX-capable `qemu-system-x86_64` available inside the runtime container.
     The default runtime image follows `../dstack-k8s/deploy/compose` and
     installs QEMU from `ppa:kobuk-team/tdx-release`.
   - WireGuard kernel support on the host. The Gateway service runs privileged
     with host networking and creates `DSTACK_E2E_GATEWAY_WG_INTERFACE`.

3. Provide an unpacked guest image store. From `meta-dstack` this is usually
   `../../../build/images`; otherwise copy `.env.example` and set:

   ```bash
   cp .env.example .env
   $EDITOR .env
   ```

The normal latest-only run needs no published KMS/Gateway image:
`dstack-gateway` and `dstack-kms` run from the local `target/release/` binaries.
The upgrade run additionally pulls its old KMS/Gateway images from Docker Hub.

## Run

From this directory, run:

```bash
DOCKER_BUILDKIT=0 docker compose --env-file .env -f compose.yml up --build --abort-on-container-exit runner
```

On TDX this latest-only path deploys two otherwise identical CVMs. Their v3
manifest requirements force `tdx_measure_acpi_tables=true` (legacy) and
`false` (lite), respectively. Both must reach `boot_progress=done`, which is
after the boot-time `GetAppKey` request, and both must serve nginx through the
Gateway.

## Run the upgrade scenario

The host-side driver is required because the runner container cannot replace
its own KMS/Gateway dependencies:

```bash
DOCKER_BUILDKIT=0 ./run-upgrade-e2e.sh
```

Defaults:

- old KMS: `dstacktee/dstack-kms:0.5.7` (pulled from Docker Hub)
- old Gateway: `dstacktee/dstack-gateway:0.5.8` (pulled from Docker Hub)
- latest KMS, Gateway, VMM, guest image: current checkout/build

The driver deliberately fails during the image-pull preflight if the exact old
image is unavailable. Override images only for intentional matrix runs:

```bash
DSTACK_E2E_OLD_KMS_IMAGE=dstacktee/dstack-kms:0.5.6 \
DSTACK_E2E_OLD_GATEWAY_IMAGE=dstacktee/dstack-gateway:0.5.8 \
  ./run-upgrade-e2e.sh
```

The upgrade sequence is:

1. Boot a forced-legacy CVM against the old KMS and old Gateway.
2. Record the KMS CA, root k256 public key, and that app's derived environment
   encryption public key.
3. Replace only KMS with the current binary while retaining its cert/key dir.
4. Require the recorded identities to be byte-for-byte stable; force-reboot the
   legacy CVM so it must provision keys from the new KMS; then boot a forced-lite
   CVM from scratch against the new KMS.
5. Flush and record Gateway WaveKV state: node UUID, CVM registrations/IPs,
   certbot config, DNS credential, ZT domain, and wildcard cert fingerprint.
6. Start rapid direct HTTP probes to both CVM WireGuard IPs, replace only the
   Gateway process, and require **zero failed probe cycles**.
7. Require all recorded Gateway state and the cert fingerprint to survive and
   verify both SNI routes through the new Gateway.

The zero-downtime assertion is specifically the CVM WireGuard data plane. The
Gateway process owns the public TLS listener, so a single-node stop/start does
not claim that the external listener itself has zero downtime. External routing
is asserted immediately before and after the upgrade.

For iterative debugging, keep the stack running:

```bash
DOCKER_BUILDKIT=0 docker compose --env-file .env -f compose.yml up --build
```

The runner leaves app VMs running by default for inspection. Set
`DSTACK_E2E_CLEANUP_AFTER=true` to remove suite VMs at the end. Stale VMs whose
names start with `DSTACK_E2E_NAME_PREFIX` are removed at the start when
`DSTACK_E2E_CLEAN_START=true`.

## What is verified

The runner checks:

1. Host-side KMS is reachable over TLS.
2. Host-side Gateway Admin API accepts configuration.
3. Gateway obtains a wildcard certificate for `*.DSTACK_E2E_BASE_DOMAIN` from
   Pebble using the mock Cloudflare DNS API.
4. VMM API becomes reachable.
5. Real nginx app CVMs boot with `kms_enabled=true` and
   `gateway_enabled=true`.
6. On TDX, v3 requirements resolve one CVM to legacy attestation and one to
   lite; both complete boot-time KMS key provisioning.
7. `curl -k` through each Gateway SNI route returns the nginx welcome page.
8. KMS and Gateway state can be captured in canonical, diffable artifacts.

`run-upgrade-e2e.sh` additionally checks KMS key continuity, Gateway persistence,
old-to-new config/storage compatibility, and zero-failure CVM WireGuard traffic
during the Gateway replacement.

Artifacts are written under `state/work/`.

## Notes / flexibility gaps

- This is a dev compose KMS/Gateway setup. KMS and Gateway key material is
  generated under `state/`; the allowlist returns `gatewayAppId = "any"`, which
  matches the host-side tdxlab-style deployment and avoids requiring Gateway to
  be a CVM.
- `dstackup install` is systemd-oriented; this suite renders `vmm.toml`,
  `kms.toml`, `gateway.toml`, and `auth-allowlist.json` itself.
- Running VMM in a container depends on the container image having a QEMU build
  that supports the target TEE platform. The runtime Dockerfile uses Intel's
  kobuk-team TDX PPA for QEMU, matching the dstack-k8s compose deployment.
- Host API is vsock-only by design. The suite therefore uses privileged host
  networking and a separate `DSTACK_E2E_HOST_API_PORT` to avoid conflicts with
  other VMM instances.
