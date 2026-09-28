# Upgrading from dstack 0.5.x to 0.6.0

Existing apps keep their identity through the upgrade: the same app ID, the
same v0 keys, and the same encrypted data disk. What changes is almost every
measurement, the service configuration, and the SDK names, so the upgrade is a
planned rollout rather than a package update. Upgrade the KMS first, then the
Gateway, then the VMM hosts, and move app CVMs to the new guest image last.

The full list of changes is in the [changelog](../CHANGELOG.md#060---2026-09-28).

## What's new

- **Guest API v1.** A versioned API, `dstack.guest.v1`, with domain-separated
  key derivation, GPU evidence, and one attestation call that works on every
  platform. The unversioned API is frozen at v0.5.11, so existing apps keep
  working. See [guest-api-v1.md](./guest-api-v1.md).
- **More platforms.** One attestation model covers Intel TDX, AMD SEV-SNP,
  AWS Nitro Enclaves, AWS NitroTPM, and GCP Confidential VMs.
- **A new guest OS.** Guest images are built with Debian and mkosi, are
  reproducible, and ship a kernel build tree for out-of-tree modules. Yocto
  images are deprecated.
- **Networking.** The VMM manages bridge and macvtap networking through
  `netd`, with vhost-net multiqueue and libvirt network filters.
- **Gateway.** Application health checks keep unhealthy instances out of load
  balancing, CVMs can connect to several Gateway clusters, and
  `dns-persist-01` issues certificates without DNS credentials
  (experimental).
- **Storage.** Data disks return deleted blocks to the host, and dm-verity
  volumes provide integrity-protected read-only data.
- **Hardening.** Every component had a security pass: bounded parsing of
  untrusted input, owner-only secrets, and authentication on every
  administrative API.

## Compatibility at a glance

| Combination | Works? |
|---|---|
| 0.5.x app, unchanged, on a 0.6.0 guest image | Yes, through the frozen v0 API |
| 0.5.8 or later KMS onboarding a 0.6.0 KMS | Yes |
| 0.5.5 or earlier KMS onboarding a 0.6.0 KMS | No; onboard a 0.5.8+ KMS first |
| 0.5.x KMS serving 0.6.0 guests | Yes, with limits (see [KMS](#1-kms)) |
| 0.5.x and 0.6.0 Gateway nodes in one cluster | Serve traffic, but do not sync |
| 0.5.x guest image on a 0.6.0 VMM | Only without `key_provider_id` (see [VMM](#3-vmm-hosts)) |
| 0.5.x SDK against a 0.6.0 guest | Yes |
| 0.6.0 SDK `DstackClient` against a 0.5.x guest | No; it now means v1 |

## Before you start

Every 0.6.0 guest image has a new `os_image_hash`, and the new KMS and Gateway
CVMs have new measurements. Register them before you deploy anything:

- add the 0.6.0 `os_image_hash` from the
  [release notes](https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.0)
  with `addOsImageHash` (see [onchain-governance.md](./onchain-governance.md))
- add the new KMS CVM's `mrAggregated` with `addKmsAggregatedMr`, and any new
  device IDs if your apps use device allowlists

The contracts need no redeploy.

Component images moved from Docker Hub to `ghcr.io/dstack-tee`, for example
`ghcr.io/dstack-tee/dstack-kms:0.6.0`. The 0.5.x images stay on Docker Hub.

The KMS and Gateway admin APIs now fail closed: with the admin API enabled but
no `auth_token` or `htpasswd_file`, the service refuses to start. Set a token
before you restart them. Old configuration files still parse, and
removed keys are ignored, so check the per-component sections below for
settings that silently stopped taking effect.

## 1. KMS

A KMS seals its root key to its own measurements, so you cannot upgrade one in
place. Deploy a 0.6.0 KMS CVM next to the old one and onboard it, which copies
the root keys over RA-TLS. The procedure is in
[deployment.md](./deployment.md#adding-kms-replicas-onboarding), with one
difference for a 0.5.x source: it has no admin listener, so leave
`source_token` empty and point `source_url` at its public RPC port.

```bash
curl -X POST "http://<new-kms>:9203/prpc/Onboard.Onboard?json" \
  -H "Content-Type: application/json" \
  -d '{"source_url": "https://<old-kms>:9201/prpc", "source_token": "", "domain": "kms.example.com"}'
```

Both sides must authorize each other first: the new KMS allows the old
`mrAggregated`, and the old KMS allows the new `mrAggregated` and the 0.6.0
`os_image_hash`. After onboarding, the KMS CA public key must match the old
one. The CA certificate itself is reissued, so compare keys, not PEM files.

The source must be 0.5.8 or later. Older sources reject the 0.6.0 certificate
format; onboard a 0.5.8+ KMS from them first, then onboard 0.6.0 from that.

Keep the old KMS running until every client has moved. While a 0.5.x KMS still
verifies 0.6.0 guests:

- it can only measure 0.6.0 guests with exactly 2 GiB or at least 2816 MiB of
  memory, and it must be able to download the 0.6.0 image
- apps using v1 `IssueCert`, and anything verifying v1 attestations, need
  0.5.9 or later

Configuration changes that affect an upgrade:

- `[rpc.tls.mutual]` and `core.admin_token_hash` are gone. Admin RPCs such as
  `ClearImageCache` now live on the `[core.admin]` listener.
- Key release on AMD SEV-SNP, AWS NitroTPM, and AWS Nitro Enclaves is off
  until you set `sev_snp_key_release`, `aws_nitro_tpm_key_release`, or
  `nitro_enclave_key_release`.
- Root-key handover is also served as `Admin.GetKmsKey`. Keep
  `core.onboard.public_key_handover = true` while any KMS still onboards
  through the public port, and turn it off afterwards.
- Auto-bootstrap refuses to overwrite existing root keys. Restore lost key
  files instead of letting the KMS regenerate them.

If you use `auth-simple`, check your policy before switching over, because
three defaults now deny boots that 0.5.x allowed:

- an empty `devices` list denies every device unless `allowAnyDevice` is true
- `allowedTcbStatuses` defaults to `["UpToDate"]`
- `allowedAdvisoryIds` defaults to `[]`, so any advisory ID on a quote denies

`auth-mock` refuses to start with an unknown `MOCK_POLICY`. `auth-eth-bun`
accepts `ETH_CHAIN_ID` and `ETH_FINALITY_CONFIRMATIONS`.

## 2. Gateway

Upgrade the Gateway after the KMS cutover. The new Gateway image changes the
Gateway app's compose hash, so whitelist the new hash on its app contract
first. Then roll the cluster one node at a time: stop a node, update its
compose to the 0.6.0 image, and start it again.
Its WaveKV data directory is migrated in place, so registrations,
certificates, and DNS credentials carry over, and traffic keeps flowing
through the other nodes.

0.5.x and 0.6.0 nodes do not sync with each other. During the rollout, avoid
admin changes and expect a CVM that registers with one version to be unknown
to the other until every node runs 0.6.0. Finish the rollout promptly.

Configuration changes:

- Set `core.admin.auth_token` (or `DSTACK_GATEWAY_ADMIN_TOKEN`). The admin API
  had no authentication in 0.5.x.
- `core.debug.insecure_skip_attestation` is gone, and a Gateway without a
  guest agent no longer starts.
- A certificate configured in `[core.proxy]` (`cert_chain`, `cert_key`) is
  ignored. Install it with `Admin.ImportCert` instead
  (see [dstack-gateway.md](./dstack-gateway.md)).

0.5.x CVMs register with a 0.6.0 Gateway unchanged, and 0.6.0 CVMs can still
register with a 0.5.x Gateway during the rollout.

## 3. VMM hosts

Install the 0.6.0 `dstack-vmm` and restart it. Running CVMs are not touched,
but each CVM picks up the new behavior on its next start.

**Check 0.5.x apps that set `key_provider_id` before you upgrade a host.** A
0.6.0 VMM writes those apps' `MRCONFIGID` in a newer format that 0.5.x guest
images reject, so the CVM fails early in boot and restarts in a loop. Move
such apps to the 0.6.0 guest image when you upgrade their host. Apps without
`key_provider_id` keep booting 0.5.x images.

Configuration changes in `vmm.toml`:

- `qemu_hotplug_off` now defaults to `true`, which changes the ACPI tables and
  RTMRs of every CVM on its next start, whatever its image. Update any
  allowlist that pins MRs. A host without GPUs can set it to `false` to keep
  its current measurements; a GPU host needs `true`.
- Bridge and macvtap networking now runs through `netd`, a privileged helper
  started as `dstack-vmm netd`. Install and start it before the VMM (see
  [bridge-networking.md](./bridge-networking.md) and
  [libvirt-network-filter.md](./libvirt-network-filter.md)). User-mode
  networking needs nothing new.
- `[auth]` now guards the whole API and web UI. `vmm-cli` takes `--token` or
  `DSTACK_VMM_TOKEN`.
- KMS and Gateway URLs are shuffled per CVM by default
  (`shuffle_kms_urls`, `shuffle_gateway_urls`).
- `image.registry` is gone; install guest images into the image directory.

Keep `gateway_urls` while any 0.5.x CVM runs on the host. The new
`gateway_clusters` setting is read only by 0.6.0 guests.

The 0.6.0 web UI writes `manifest_version: "3"` when you move an app to a
0.6.0 image, and 0.5.x images cannot read it. To roll such an app back to a
0.5.x image, recreate it with `vmm-cli`.

## 4. Apps

Moving an app CVM to the 0.6.0 guest image keeps its app ID, its v0 keys, and
its data disk. The disk key is derived exactly as before, and the LUKS and ZFS
formats are unchanged. Back up the data anyway: this path is not covered by
the release tests.

To upgrade, change only the image. The compose hash stays the same as long as
the app-compose bytes do, so nothing new needs whitelisting beyond the
`os_image_hash`.

Behavior an app may notice after the move:

- Data disks now release deleted blocks to the host, and the first boot starts
  a one-time `zpool trim`. Set `storage_discard: false` to opt out, which
  changes the compose hash.
- `EmitEvent` always fails, because runtime RTMR3 events are system-owned.
  Bind app data through `report_data` instead.
- `GetQuote` answers on Intel TDX only. Use `Attest` on other platforms.

## 5. SDKs

Apps keep working with their 0.5.x SDK. When you update to the 0.6.0 SDK, the
unsuffixed `DstackClient` means the v1 client, which needs a 0.6.0 guest. To
stay on the v0 API, rename it:

```python
from dstack_sdk import DstackClientV0

client = DstackClientV0()
```

```ts
import { DstackClientV0 } from '@phala/dstack-sdk'

const client = new DstackClientV0()
```

Deep imports of the v0 modules gain a `_v0` suffix, for example
`dstack_sdk.dstack_client_v0`. The Python v0 client emits a
`DeprecationWarning`, which fails test suites that turn warnings into errors.
JavaScript v0 methods now reject on failure instead of resolving to an empty
object, and the wallet adapters reject TLS keys.

**Moving to v1 changes your keys.** v1 `GetKey` derives different keys from
v0 for the same name. Derive the v1 key, move any assets with a transaction
signed by the v0 key, and only then switch. See
[the v1 migration guide](./guest-api-v1.md#migration-from-the-unversioned-api).

**Recheck compose hashes computed with the Go or Python SDK.** Before 0.6.0,
those helpers dropped some app-compose fields, and Go escaped `<`, `>` and
`&`, so the hash you whitelisted may not match what the CVM measures. Recompute
it with the 0.6.0 SDK, whitelist the correct value, and remove the stale one.
