<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# Production-compatible KMS/Gateway upgrade E2E

This suite runs the stateful services and applications in **real TDX CVMs**.
Docker Compose is used only for host infrastructure (VMM, authorization,
Local-Key-Provider, image server, and mock ACME/DNS):

```text
host Docker Compose
  ├─ dstack-vmm + dstack-auth
  ├─ AESMD + SGX Local-Key-Provider
  ├─ verified OS/image artifact server
  └─ Pebble + mock Cloudflare DNS

real TDX CVMs
  ├─ KMS 0.5.8 (Local-Key-Provider, quote-enabled onboarding)
  ├─ current KMS (new CVM, quote-attested replication from 0.5.8)
  ├─ two-node Gateway 0.5.8 cluster, rolled one node at a time to current
  ├─ forced-legacy nginx app CVM
  └─ forced-lite nginx app CVM
```

The upgrade scenario intentionally rejects the development trust settings that
would make a passing result irrelevant to production:

- KMS 0.5.8 uses `quote_enabled = true`.
- Both KMS manifests explicitly set `enforce_self_authorization = true`.
- KMS OS image verification is enabled and downloads a checksum-verified image
  archive from an initially empty cache.
- KMS root keys and Gateway TLS identity are created inside TDX CVMs; the suite
  never generates or injects them on the host.
- The authorization webhook pins one OS digest, exact KMS aggregate
  measurements, the quote-derived physical TDX device ID, exact app compose
  hashes, and a concrete 20-byte Gateway app ID. `allowAnyDevice = true` and
  `gatewayAppId = "any"` are rejected.
- Container references in measured app manifests are content-addressed Docker
  image IDs. Tags are used only as the Docker Hub/build inputs that are pulled,
  inspected, saved, and imported before boot.

## Prerequisites

1. Build the host-side control binaries:

   ```bash
   cargo build --release --manifest-path ../../dstack/Cargo.toml \
     -p dstack-cli -p dstack-auth -p dstack-vmm -p supervisor
   ```

   The driver builds current KMS and Gateway binaries for
   `x86_64-unknown-linux-musl` and places them in test-only container images.
   The static binaries are layered on the released 0.5.8 production runtime;
   the KMS production builder still uses the same Debian/QEMU revision, and the
   current Gateway entrypoint is copied from this checkout. The built binaries
   and in-CVM version endpoints must report the current workspace version and
   Git revision, so Docker cache or an old binary cannot silently turn the
   upgrade into a no-op.

2. Provide a TDX/SGX host with:

   - `/dev/kvm`, `/dev/vhost-vsock`, Intel TDX, and QGS (default port `4050`)
   - `/dev/sgx_enclave` and `/dev/sgx_provision`
   - a working host SGX QCNL configuration at `/etc/sgx_default_qcnl.conf`
     whose PCCS is provisioned for this physical platform; override its path
     with `DSTACK_E2E_QCNL_CONF` when needed. A public PCCS only works after
     this platform's PCK certificate has been registered there.
   - an IPv4/DNS name for the host that is reachable from both the host-side
     deployment client and QEMU user-networked CVMs; the suite derives
     `<default-route-ip>.nip.io`, or accepts `DSTACK_E2E_KMS_RPC_DOMAIN`
   - Docker and WireGuard kernel support

3. Provide an unpacked dstack image directory containing `digest.txt` and
   `sha256sum.txt` for both the current image (`DSTACK_E2E_IMAGE_NAME`) and the
   v0.5.11 compatibility image (`DSTACK_E2E_OLD_IMAGE_NAME`). Copy
   `.env.example` to `.env` when paths or ports differ.

## Run

```bash
DOCKER_BUILDKIT=0 ./run-upgrade-e2e.sh
```

The defaults pull these released images from Docker Hub:

- `dstacktee/dstack-kms:0.5.8@sha256:9650dcb47dad0065470f432f00e78e012912214ef1a5b1d7272918817e61a26d`
- `dstacktee/dstack-gateway:0.5.8@sha256:6eb1dc1a5000f37cc5b0322d3fdb71e7f2e31859b5e3a611634919278cee2411`

The driver checks each released binary's `--version` output before deploying
anything. Set `DSTACK_E2E_SKIP_CURRENT_BUILD=true` only when the current musl
binaries were already built.

## Upgrade sequence and assertions

### KMS 0.5.8 to current

1. Deploy KMS 0.5.8 as a Local-Key-Provider TDX CVM with no pre-created keys.
2. Call `Onboard.GetAttestationInfo`, authorize its exact `mrAggregated`, then
   bootstrap it. The bootstrap response must contain non-empty attestation.
3. Boot the forced-legacy app through KMS 0.5.8 and record the KMS CA SPKI,
   root k256 public key, and the app's derived environment-encryption public
   key. (The expected onboarding path reissues the self-signed CA certificate,
   so its DER bytes/expiry are not a stable identity; its private key/SPKI is.)
4. Deploy current KMS in a new Local-Key-Provider TDX CVM, authorize its exact
   measurement, and call `Onboard.Onboard` against KMS 0.5.8. This exercises the
   production RA-TLS root-key replication path; it is not a directory copy.
5. Require all recorded identities/derived keys to be byte-for-byte equal,
   stop KMS 0.5.8, and force the legacy app to boot against only current KMS.
6. Boot a fresh forced-lite app against current KMS. Both modes must reach
   `boot_progress=done`, which occurs after boot-time `GetAppKey` succeeds.

The artifact server journal must contain two successful GETs for the exact
measured OS archive (one from each fresh KMS data disk). VM logs are also
rejected if they say image verification or self-authorization is disabled.

### Gateway 0.5.8 to current

1. Deploy two Gateway 0.5.8 TDX CVMs under one pinned Gateway app ID. Both get
   app keys and RA-TLS certificates from KMS; their environment is encrypted by
   VMM/KMS.
2. Form a WaveKV cluster, configure Pebble/Cloudflare mock DNS once, and require
   the second node to receive the configuration and wildcard certificate.
3. Verify the legacy and lite app SNI routes through **both** Gateway nodes.
4. Snapshot each node's UUID, CVM registrations/IPs, certbot configuration, DNS
   credential metadata, ZT domains, and wildcard-certificate fingerprint.
5. Run a rapid HA probe that alternates the preferred physical Gateway for
   every legacy/lite request and falls back to the other node in the same cycle.
6. Stop, update the measured app compose, and restart node 1 on current KMS;
   require it to carry both apps and retain all durable state. Repeat for node 2.
7. Require zero failed HA cycles and unchanged durable state/certificates.
8. Force certificate issuance through each upgraded node against a mock DNS API
   that rejects anything except the original bearer token. This proves the DNS
   credential value survived even though the current admin API redacts it.
9. Reconcile CAA through each upgraded node, then rotate the shared ACME account
   through one node and issue through the other. These are the two admin
   operations that take the cluster-wide ACME lock, and nothing else in the
   suite calls them: a reconciliation that refuses or blocks on the lock it
   holds itself is invisible to single-process unit tests. The zone is read back
   from the mock provider after each step and must carry exactly one `issue` and
   one `issuewild` record, both pinned to the same account -- the rotated one
   after rotation -- with no `;` guard left behind.

This is a production-style **rolling two-node** zero-downtime assertion. The
suite does not claim that rebooting a single Gateway CVM can preserve that
node's listener; availability is maintained by the peer, as it must be in a
production rollout.

Artifacts, manifests, version headers, canonical state snapshots, probe
results, attestation information, and VM logs are written to `state/work/`.
The stack is retained by default for inspection; set
`DSTACK_E2E_KEEP_STACK=false` and/or `DSTACK_E2E_CLEANUP_AFTER=true` to clean it.
