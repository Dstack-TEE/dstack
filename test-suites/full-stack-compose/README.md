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
       ├─ deploys nginx test app CVM with kms_enabled=true + gateway_enabled=true
       └─ verifies HTTPS Gateway -> app routing
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

No Gateway image publishing is needed in this architecture: `dstack-gateway` and
`dstack-kms` are run from the local `target/release/` binaries on the host side.

## Run

From this directory, run:

```bash
DOCKER_BUILDKIT=0 docker compose --env-file .env -f compose.yml up --build --abort-on-container-exit runner
```

For iterative debugging, keep the stack running:

```bash
DOCKER_BUILDKIT=0 docker compose --env-file .env -f compose.yml up --build
```

The runner leaves the app VM running by default for inspection. Set
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
5. A real nginx app CVM boots with `kms_enabled=true` and `gateway_enabled=true`.
6. `curl -k` through the Gateway SNI route returns the nginx welcome page.

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
