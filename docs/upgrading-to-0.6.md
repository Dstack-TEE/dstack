# Upgrading from dstack 0.5.x to 0.6.0

Most apps move to 0.6.0 by switching the guest image. They keep their app ID,
their keys, and their encrypted data disk, and the 0.5.x guest API keeps
working unchanged. A few changes in the new guest OS can still stop an app
from starting, so read [Upgrading an app](#upgrading-an-app) before you switch.

If you run your own dstack infrastructure, upgrade it first, in this order:
KMS, Gateway, then VMM hosts. See
[Upgrading the infrastructure](#upgrading-the-infrastructure).

The full list of changes is in the [changelog](../CHANGELOG.md#060---2026-09-28).

## What's new

- **Guest API v1.** A versioned API, `dstack.guest.v1`, with domain-separated
  key derivation, GPU evidence, and one attestation call that works on every
  platform. See [guest-api-v1.md](./guest-api-v1.md).
- **More platforms.** One attestation model covers Intel TDX, AMD SEV-SNP,
  AWS Nitro Enclaves, AWS NitroTPM, and GCP Confidential VMs.
- **A new guest OS.** Guest images are built with Debian and mkosi, are
  reproducible, and ship a kernel build tree for out-of-tree modules.
- **Gateway health checks.** An app can opt in to keep unhealthy instances out
  of load balancing (see [app-health-checks.md](./app-health-checks.md)).
- **Networking and storage.** Bridge and macvtap networking with vhost-net
  multiqueue, dm-verity volumes, and data disks that return deleted blocks to
  the host.
- **Hardening.** Every component had a security pass, and every
  administrative API now requires authentication.

## Upgrading an app

### Breaking changes to check

Go through this list before you switch the image. Each item can stop an app
from starting, or change what it sees.

**`pre_launch_script` runs in strict mode.** The script is now sourced under
`set -euo pipefail`, so an unset variable or a failing command aborts the app
start. Give optional variables a default and guard commands that may fail:

```bash
# 0.5.x: silently empty when DSTACK_DOCKER_USERNAME is not set
if [[ -n "$DSTACK_DOCKER_USERNAME" ]]; then ...

# 0.6.0
if [[ -n "${DSTACK_DOCKER_USERNAME:-}" ]]; then ...
docker login ... || echo "registry login failed"
```

**GPU CVMs must pass GPU attestation to boot.** When a GPU is attached, the
guest now attests it at boot and stops if the GPU is not in confidential
computing mode, has debug or DevTools mode on, lacks secure boot, or cannot be
attested. This applies to 0.5.x app-compose files too. Attestation needs
outbound access to NVIDIA's RIM and OCSP services. To boot without it, opt out
explicitly, which changes the compose hash:

```json
{
  "manifest_version": "3",
  "requirements": {
    "gpu_policy": { "attest_gpu": false }
  }
}
```

**Legacy iptables is gone.** The guest kernel only has nf_tables. Containers
that call `iptables-legacy`, or images that default to it (some VPN,
WireGuard, and firewall images), fail. Switch them to `iptables-nft`. See
[guest-netfilter-capabilities.md](./guest-netfilter-capabilities.md).

**Environment variables arrive exactly as encrypted.** In 0.5.x a newline in a
value reached the container as the two characters `\n`, and a trailing
backslash could swallow the next variable. Now the app gets the value byte
for byte. An app that converts `\n` back into newlines, for example in a PEM
key, keeps working; one that relies on the escaped form must change.

**An encrypted environment that cannot be decrypted stops the boot.** 0.5.x
dropped it silently and started the app without its secrets. This happens
when an app ships encrypted environment variables but runs without a KMS.

**Two guest API calls changed behavior.** `EmitEvent` always fails, because
runtime RTMR3 events are now owned by the system; bind your data through
`report_data` in a quote instead. `GetQuote` answers on Intel TDX only; use
`Attest` on other platforms. Every other call of the 0.5.x API behaves as
before (see [guest-api-v0.md](./guest-api-v0.md)).

**`manifest_version` must be 1, 2, or a string.** A numeric value above 2 is
rejected. Write newer versions as strings, for example `"3"`.

### What stays the same

The app ID, the v0 keys from `GetKey`, and the data disk carry over, because
the disk key is derived as before and the disk format is unchanged. Socket
paths (`/var/run/dstack.sock`, `/var/run/tappd.sock`), the `/dstack` working
directory, allowed environment variable names, and `docker_config` all work as
before. Back up important data anyway, since the release tests do not cover
moving a data disk between image versions.

The container runtime moves to newer versions of the same tools:

| | 0.5.x | 0.6.0 |
|---|---|---|
| Linux kernel | 6.9 | 6.18 |
| Docker Engine | 25.0 | 26.1 |
| Docker Compose | 2.26.0 | 2.26.1 |
| NVIDIA driver | 595.58.03 | 595.91.07 |
| NVIDIA Container Toolkit | 1.14 | 1.19 |

### Improvements you may notice

- Containers can use more than one CPU (`cpus: 2`); 0.5.x pinned Docker to
  CPU 0.
- With compose `include:`, containers from included files are no longer
  removed as orphans on reboot.
- The app starts only after the guest agent is ready, so
  `/var/run/dstack.sock` is always available to it.
- A Gateway registration failure no longer stops the boot.
- The data disk releases deleted blocks to the host, and the first boot on
  0.6.0 starts a one-time `zpool trim`. Set `storage_discard: false` to opt
  out, which changes the compose hash.

### Updating the SDK

Apps keep working with the 0.5.x SDK. In the 0.6.0 SDK, the unsuffixed
`DstackClient` means the v1 client, which needs a 0.6.0 guest. To stay on the
0.5.x API, rename it:

```python
from dstack_sdk import DstackClientV0

client = DstackClientV0()
```

```ts
import { DstackClientV0 } from '@phala/dstack-sdk'

const client = new DstackClientV0()
```

Other changes in the 0.6.0 SDK:

- Deep imports of the v0 modules gain a `_v0` suffix, for example
  `dstack_sdk.dstack_client_v0`.
- The Python v0 client emits a `DeprecationWarning`, which fails test suites
  that turn warnings into errors.
- JavaScript v0 methods reject on failure instead of resolving to an empty
  object.
- The wallet adapters reject TLS keys; derive wallets from `get_key()`.

**Recheck compose hashes computed with the Go or Python SDK.** Before 0.6.0,
those helpers dropped some app-compose fields, and Go escaped `<`, `>` and
`&`, so a whitelisted hash may not match what the CVM measures. Recompute it
with the 0.6.0 SDK, whitelist the correct value, and remove the stale one.

### Moving to guest API v1

Moving is optional. **v1 `GetKey` derives different keys from v0 for the same
name**, so an app that holds assets under a v0 key must migrate them: derive
the v1 key, move the assets with a transaction signed by the v0 key, and only
then switch. v1 attestations and v1-issued RA-TLS certificates also need KMS
and verifiers 0.5.9 or later. See
[the v1 migration guide](./guest-api-v1.md#migration-from-the-unversioned-api).

### Switching the image

1. Check the breaking changes above, and update the app-compose if needed.
2. Whitelist the 0.6.0 `os_image_hash` from the
   [release notes](https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.0)
   with `addOsImageHash` (see [onchain-governance.md](./onchain-governance.md)).
   If you changed the app-compose, whitelist its new compose hash too.
3. Update the CVM to the 0.6.0 image and restart it.

Unchanged app-compose bytes keep the same compose hash. The 0.6.0 web UI
writes `manifest_version: "3"` when you move an app to a 0.6.0 image, which
changes the hash and prevents rolling back to a 0.5.x image. Use `vmm-cli` if
you need to keep the hash.

## Upgrading the infrastructure

This section is for operators who run their own KMS, Gateway, and VMM.

Register the new measurements before you deploy: the 0.6.0 `os_image_hash`,
the new KMS CVM's `mrAggregated` (`addKmsAggregatedMr`), and the new compose
hashes of the KMS and Gateway apps. The contracts need no redeploy. Component
images moved from Docker Hub to `ghcr.io/dstack-tee`, for example
`ghcr.io/dstack-tee/dstack-kms:0.6.0`.

The KMS and Gateway admin APIs now fail closed: with the admin API enabled but
no `auth_token` or `htpasswd_file`, the service refuses to start. Old
configuration files still parse, and removed keys are ignored.

| Combination | Works? |
|---|---|
| 0.5.8 or later KMS onboarding a 0.6.0 KMS | Yes |
| 0.5.5 or earlier KMS onboarding a 0.6.0 KMS | No; onboard a 0.5.8+ KMS first |
| 0.5.x KMS serving 0.6.0 guests | Yes, with limits (see [KMS](#kms)) |
| 0.5.x and 0.6.0 Gateway nodes in one cluster | Serve traffic, but do not sync |
| 0.5.x guest image on a 0.6.0 VMM | Only without `key_provider_id` |

### KMS

A KMS seals its root key to its own measurements, so you cannot upgrade one in
place. Deploy a 0.6.0 KMS CVM next to the old one and onboard it, following
[deployment.md](./deployment.md#adding-kms-replicas-onboarding). A 0.5.x source
has no admin listener, so leave `source_token` empty and point `source_url` at
its public RPC port:

```bash
curl -X POST "http://<new-kms>:9203/prpc/Onboard.Onboard?json" \
  -H "Content-Type: application/json" \
  -d '{"source_url": "https://<old-kms>:9201/prpc", "source_token": "", "domain": "kms.example.com"}'
```

Both sides must authorize each other first: the new KMS allows the old
`mrAggregated`, and the old KMS allows the new `mrAggregated` and the 0.6.0
`os_image_hash`. After onboarding, compare the KMS CA public keys; the CA
certificate itself is reissued. The source must be 0.5.8 or later.

Keep the old KMS running until every client has moved. While a 0.5.x KMS still
verifies 0.6.0 guests, it can only measure guests with exactly 2 GiB or at
least 2816 MiB of memory, and it must be able to download the 0.6.0 image.

Configuration changes:

- `[rpc.tls.mutual]` and `core.admin_token_hash` are gone. Admin RPCs such as
  `ClearImageCache` now live on the `[core.admin]` listener.
- Key release on AMD SEV-SNP, AWS NitroTPM, and AWS Nitro Enclaves stays off
  until you set `sev_snp_key_release`, `aws_nitro_tpm_key_release`, or
  `nitro_enclave_key_release`.
- Keep `core.onboard.public_key_handover = true` while any KMS still onboards
  through the public port, and turn it off afterwards.
- Auto-bootstrap refuses to overwrite existing root keys.

If you use `auth-simple`, three defaults now deny boots that 0.5.x allowed: an
empty `devices` list denies every device unless `allowAnyDevice` is true,
`allowedTcbStatuses` defaults to `["UpToDate"]`, and any advisory ID on a
quote denies unless listed in `allowedAdvisoryIds`.

### Gateway

Upgrade the Gateway after the KMS cutover, one node at a time: stop a node,
update its compose to the 0.6.0 image, and start it again. Its data directory
is migrated in place, so registrations, certificates, and DNS credentials
carry over, and traffic keeps flowing through the other nodes.

0.5.x and 0.6.0 nodes do not sync with each other, so avoid admin changes
during the rollout and finish it promptly. Configuration changes:

- Set `core.admin.auth_token`; the admin API had no authentication in 0.5.x.
- `core.debug.insecure_skip_attestation` is gone, and a Gateway without a
  guest agent no longer starts.
- A certificate configured in `[core.proxy]` is ignored. Install it with
  `Admin.ImportCert` instead (see [dstack-gateway.md](./dstack-gateway.md)).

### VMM hosts

Install the 0.6.0 `dstack-vmm` and restart it. Running CVMs are not touched,
but each picks up the new behavior on its next start.

**Check 0.5.x apps that set `key_provider_id` first.** A 0.6.0 VMM writes
their `MRCONFIGID` in a format that 0.5.x guest images reject, so the CVM
restarts in a loop. Move those apps to the 0.6.0 image when you upgrade their
host.

Configuration changes in `vmm.toml`:

- `qemu_hotplug_off` defaults to `true`, which changes the ACPI tables and
  RTMRs of every CVM on its next start. Update any allowlist that pins MRs. A
  host without GPUs can set it to `false` to keep its measurements.
- Bridge and macvtap networking runs through `netd`, started as
  `dstack-vmm netd`. Install it before the VMM (see
  [bridge-networking.md](./bridge-networking.md)).
- `[auth]` now guards the whole API and web UI. `vmm-cli` takes `--token` or
  `DSTACK_VMM_TOKEN`.
- Keep `gateway_urls` while any 0.5.x CVM runs on the host; the new
  `gateway_clusters` setting is read only by 0.6.0 guests.
