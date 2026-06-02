# Upgrading dstack-kms

> Audience: operators upgrading or replacing a `dstack-kms` instance inside an existing cluster.
>
> Background reading: [Verification overview](../verification.md) and the [Attestation Verification tutorial](../tutorials/attestation-verification.md).

## 1. Why a KMS cluster, and why upgrade is a cluster operation

`dstack-kms` is the key authority for every app deployed under it: it issues the keys that decrypt env files, derive app-scoped secrets, and authenticate RA-TLS. Those keys all descend from a root that the KMS instance holds.

The KMS root is held by a **local key provider** inside the CVM: it is sealed to the CVM's TDX measurement set. Sealing has two consequences relevant here:

- The root cannot be exfiltrated; only a CVM with matching MRs can unseal it.
- The root cannot survive an MR change. Any binary upgrade, OS upgrade, or compose change that alters MRTD/RTMR0-3 produces a CVM that cannot unseal the previous root. A single-instance KMS that goes through an upgrade — or simply restarts on a host whose firmware changed — loses its root and every key derived from it. All apps tied to that KMS become unrecoverable.

The KMS cluster protocol exists to make this survivable. When a new instance is brought up, it does not generate a fresh root — it calls `onboard` on an existing peer, which transfers the root over an attested channel after verifying the new instance's quote. Once two or more instances hold the root, any one of them can be retired (or upgraded by replacement) without losing the root.

Consequence for operators:

- A KMS in production must be a cluster of at least two instances. Single-instance deployments cannot be upgraded without key loss.
- "Upgrading the KMS" always means: stand up a new instance running the target version, onboard it from an existing peer, then decommission the old peer. The [bridge approach](#6-the-bridge-upgrade-approach) is just this sequence applied when the new instance's measurements are not directly verifiable by the existing peer.

## 2. The onboard verification constraint

The `onboard` RPC's verifier strictly compares the new instance's quote MRTD/RTMR0/RTMR1/RTMR2 against expected values reconstructed from `vm_config` and the OS image. There is no bypass: any mismatch rejects the onboard, and the new instance cannot receive the root.

The actual values in the quote come from the new instance's **OS firmware** and the VMM host's **QEMU**. The `dstack-kms` binary inside the new instance affects RTMR3 (compose hash), not RTMR0-2. Consequence:

> A new KMS binary can run inside a CVM whose OS the current source verifier can already handle. The OS choice is gated by source capability; the binary choice is not.

That single fact is what makes the [bridge approach](#6-the-bridge-upgrade-approach) work.

## 3. Known release boundaries

> ⚠️ **Do not use the `v0.5.10` build of `dstack-kms`.** It shipped with the legacy 13-event RTMR0 logic but ran against the new edk2-stable202505 firmware introduced by dstack-os 0.5.10, so it cannot verify any quote produced by that OS. No `kms-v0.5.10` tag was ever cut; `kms-v0.5.11` is the hotfix that supersedes it. If a cluster is currently running this build, treat it as your starting point only long enough to bridge through to `kms-v0.5.11` + [PR #693](https://github.com/Dstack-TEE/dstack/pull/693).

Upgrades rarely jump directly from an old source to the latest target. Three breaking changes between 0.5.4 and the master branch force staging:

| Boundary | Side | What changed | Why it forces staging |
|---|---|---|---|
| 0.5.4 → 0.5.5 | KMS / VMM | `VmConfig` schema gained `qemu_version`, `image`, `host_share_mode`. RTMR3 event log started recording filesystem type. `VmConfig` decode error fixed (#347). | A 0.5.4 source's verifier hardcodes a QEMU base — a bridge built on a newer VMM emits a `vm_config` and `vm_config.qemu_version` it cannot interpret. State written by 0.5.4 is read by ≥0.5.5 binaries through serde defaults, but only if the bridge first lands on 0.5.5 itself. |
| 0.5.8 → 0.5.9 | KMS | KMS introduced explicit MR allowlist plus self-authorization on trusted RPCs ([c8cddc31](https://github.com/Dstack-TEE/dstack/commit/c8cddc31), [06d89a29](https://github.com/Dstack-TEE/dstack/commit/06d89a29), [d3c2ca13](https://github.com/Dstack-TEE/dstack/commit/d3c2ca13)). The V1 attestation envelope was redesigned to a CBOR platform/stack schema ([ae8a9353](https://github.com/Dstack-TEE/dstack/commit/ae8a9353)). | A 0.5.8 source cannot interpret the new attestation/auth fields that a 0.5.9-and-later bridge sends during onboard. Going through 0.5.9 first puts the configuration knobs (allowlist entries, self-auth enforcement) in place before stricter binaries take over. |
| dstack-os 0.5.9 → 0.5.10 | meta-dstack (OS) | OVMF upgraded from a 2024-09 untagged snapshot to `edk2-stable202505` (`f9f11f3` on meta-dstack). RTMR0 went from 13 to 17 events. | Any source verifier without `OvmfVariant` dispatch (every KMS ≤ 0.5.10) cannot verify a bridge whose OS is 0.5.10+. `kms-v0.5.11` is the first release that knows the new event layout. |

Releases that did not introduce verification-relevant breaks:

- 0.5.5 → 0.5.6 → 0.5.7 — incremental, no schema or auth changes (dstack repo skipped a 0.5.6 release tag; meta-dstack published 0.5.6 / 0.5.6.1 OS images during this window).
- 0.5.7 → 0.5.8 — KMS HTTP helper refactor only.
- `v0.5.10` repo tag — see the warning above; this build is broken in practice and is treated here only as a "current source" you migrate *away* from, never as a target.
- `kms-v0.5.11` → master + [PR #693](https://github.com/Dstack-TEE/dstack/pull/693) — closes the OVMF variant resolution gap for `dstack-X.Y.Z-<HEXHASH>` directory naming, but no new schema.

## 4. Recommended upgrade staircase

```
0.5.4 ──[A]──► 0.5.5 ──► 0.5.7 ──► 0.5.9 ──[C]──► kms-v0.5.11 + PR #693
              \─── any 0.5.5+ release in this range ───/
                                  \─[B]
```

- [A]: VmConfig / app-compose schema break (forced hop).
- [B]: KMS auth + attestation envelope break (forced hop).
- [C]: OVMF variant dispatch added (required to onboard CVMs on dstack-os 0.5.10+).

Within each segment any minor-version pair works as a single hop (e.g. 0.5.5 → 0.5.7 → 0.5.8 are equivalent landings). Across a boundary you must stop at the version on the right side of the arrow before continuing.

### Per-hop bridge configuration

Each hop reuses the same [bridge pattern](#6-the-bridge-upgrade-approach). The bridge's OS firmware must be in a range the *current source* can verify; the bridge's in-container `dstack-kms` binary is the *target* of that hop.

| Hop | Current source KMS | Bridge VMM | Bridge OS firmware | Bridge KMS binary (= next source) |
|---|---|---|---|---|
| H1 (boundary A) | 0.5.4 | matched to 0.5.4's hardcoded QEMU base — see [R1](#r1-kms-054-schema-break) | dstack-os 0.5.4 era (Pre202505) | dstack-kms 0.5.5 |
| H2 (within segment) | 0.5.5 – 0.5.8 | any 0.5.5+ | any Pre202505-era dstack-os | the highest 0.5.5–0.5.8 release in your supply chain (often 0.5.7 or 0.5.8) |
| H3 (boundary B) | 0.5.7 / 0.5.8 | any 0.5.5+ | any Pre202505-era dstack-os | dstack-kms 0.5.9 |
| H4 (boundary C) | 0.5.9 | any 0.5.5+ | dstack-os ≤ 0.5.9 (Pre202505 — required by the 0.5.9 verifier) | dstack-kms `kms-v0.5.11` + [PR #693](https://github.com/Dstack-TEE/dstack/pull/693) |
| H5 (optional) | kms-v0.5.11 + PR #693 | 0.5.11+ writing `ovmf_variant` | dstack-os 0.5.10+ | same target (only if you want the source CVM itself on a newer OS) |

Notes:

- H2 may collapse to zero hops if you only ever ran 0.5.5+ to begin with.
- "Next source" entries are *not* the master branch directly — they are intermediate landings. Combining boundary jumps (e.g. H1 + H3 in one go) means a 0.5.4 source receives a quote produced by a binary whose `vm_config` schema, auth model, and attestation envelope all changed at once. Stage instead.
- H4's OS constraint comes from §3 boundary C: a 0.5.9 source has no OvmfVariant dispatch.
- After H4 finishes, the cluster can onboard any subsequent CVM on any OS in the verifier's supported range.

After the staircase is complete, subsequent onboards no longer require a bridge — they are normal cluster additions.

## 5. Verifier capability by KMS release

The verifier shipped with each KMS release determines what bridge configurations the playbook above can recommend.

| KMS release | VmConfig schema | QEMU runtime | OVMF variants |
|---|---|---|---|
| 0.5.4 | `spec_version=1`; no `qemu_version` | hardcoded QEMU base | Pre202505 only |
| 0.5.5 – 0.5.9 | + `qemu_version`, `image`, `host_share_mode` | `QEMU_ACPI_COMPAT_VER` env var | Pre202505 only |
| `v0.5.10` tag | same as 0.5.9 | env var | **DO NOT USE.** Ships the pre-OvmfVariant verifier alongside the new dstack-os 0.5.10 firmware, so it cannot verify any quote that firmware produces. No `kms-v0.5.10` tag exists — `kms-v0.5.11` is the hotfix. |
| `kms-v0.5.11` ([PR #678](https://github.com/Dstack-TEE/dstack/pull/678)) | + `ovmf_variant` (Optional) | env var | Pre202505 + Stable202505 — resolution from `vm_config.ovmf_variant` → directory name fallback (unreliable for `dstack-X.Y.Z-<HEXHASH>` dirs) |
| `kms-v0.5.11` + [PR #693](https://github.com/Dstack-TEE/dstack/pull/693) | same | env var | Pre202505 + Stable202505 — resolution from `vm_config.ovmf_variant` → `metadata.json.version` → directory name fallback |

OS firmware mapping (per `dstack-mr/src/lib.rs:29`):

- dstack-os ≤ 0.5.9 emits the 13-event Pre202505 layout
- dstack-os 0.5.10 and later emits the 17-event edk2-stable202505 layout

## 6. The bridge upgrade approach

```
Initial:  source = dstack-kms A on dstack-os X
Bridge:   build CVM = dstack-kms B on dstack-os Y, where Y is the bridge OS recommended for A
          onboard the bridge → verified ✓
          bridge becomes the new source
After:    source = dstack-kms B on dstack-os Y; new onboards apply B's capability
```

The `dstack-kms` binary inside the bridge does not affect verification; the OS does. For the choice of `(B, Y)` for any given current source `A`, follow the [staircase](#4-recommended-upgrade-staircase).

**Single-hop**: the bridge becomes the long-running source on `Y`.

**Two-hop**: after the bridge takes over, onboard a final source on a newer OS `Z`. The bridge (running `B`) verifies it; the bridge is then decommissioned. Use when the source CVM should run a fresher OS.

## 7. Pre-flight verification with `dstack-mr diagnose`

[PR #679](https://github.com/Dstack-TEE/dstack/pull/679) adds a `diagnose` subcommand that reproduces the verifier's RTMR0 computation locally — confirm `RTMR0: MATCH` before the actual onboard call.

### Tooling

`dstack-mr` shells out to `dstack-acpi-tables`, a patched QEMU 9.2.1 binary built from [`kvinwang/qemu-tdx`](https://github.com/kvinwang/qemu-tdx) (branch `dstack-qemu-9.2.1`, pinned at `dbcec07c0854bf873d346a09e87e4c993ccf2633`). The [Attestation Verification tutorial](../tutorials/attestation-verification.md#step-3-calculate-expected-measurements) covers building it from source. A faster path is extracting the prebuilt binary from the official KMS image:

```bash
docker pull dstacktee/dstack-kms:0.5.11
docker create --name x dstacktee/dstack-kms:0.5.11
docker cp x:/usr/local/bin/dstack-acpi-tables ./
docker cp x:/usr/local/share/qemu/efi-virtio.rom ./
docker cp x:/usr/local/share/qemu/kvmvapic.bin ./
docker cp x:/usr/local/share/qemu/linuxboot_dma.bin ./
docker rm x

sudo apt-get install -y libglib2.0-0t64 libpixman-1-0 libslirp0
sudo install -m 755 dstack-acpi-tables /usr/local/bin/
sudo install -d /usr/local/share/qemu
sudo install -m 644 efi-virtio.rom kvmvapic.bin linuxboot_dma.bin /usr/local/share/qemu/
```

Build `dstack-mr` from the diagnose branch:

```bash
git fetch origin feat/dstack-mr-diagnose
git checkout feat/dstack-mr-diagnose
cargo build --release -p dstack-mr-cli
```

### Run

```bash
# Extract the bridge's vm_config (replace VM_RUN_DIR with your VMM's run directory)
jq -r .vm_config "$VM_RUN_DIR/<vm-id>/shared/.sys-config.json" > /tmp/vm_config.json

./target/release/dstack-mr diagnose \
  --vm-config /tmp/vm_config.json \
  --image-dir "$DSTACK_IMAGES_DIR/<bridge-os-image-dir>" \
  --actual-rtmr0 <hex_from_bridge_quote>
```

Expected for a healthy bridge: the printed `ovmf_variant` matches the bridge OS's firmware range and the final comparison line reads `RTMR0: MATCH`. On `RTMR0: MISMATCH`, the `=== RTMR0 event log ===` section labels each event semantically so the first divergent entry can be localised.

## 8. Risks and edge cases

### R1. KMS 0.5.4 schema break

The 0.5.4 verifier ignores `vm_config.qemu_version` and uses a hardcoded QEMU base. A bridge whose QEMU does not match that base produces an `acpi_loader` hash 0.5.4 cannot reproduce, regardless of OVMF variant compatibility. Mitigation: capture a known-working CVM's `vm_config` + quote from the existing 0.5.4 cluster, run `dstack-mr diagnose` to identify the implicit QEMU base, and either match it on the bridge or stage through a 0.5.5+ intermediate source first.

### R2. Custom builds diverging from upstream

A deployment running a private branch may carry capabilities upstream master lacks (for example, per-version `dstack-acpi-tables` binaries dispatched by `qemu_version`). Before adopting a master-derived target build, verify that any divergence does not regress your cluster — typically only matters when CVMs in one cluster span multiple QEMU major versions.

### R3. KMS state forward compatibility

The bridge inherits sealed root keys and CA from the old source over the onboard protocol; the new binary must read that state. Stable in practice for 0.5.5 → master; verify with a dry run when crossing the 0.5.4 → 0.5.5+ boundary.

### R4. Measurement cache invalidation

`MEASUREMENT_CACHE_VERSION` (in `verifier/src/verification.rs`) is bumped whenever expected RTMR computation changes; newer binaries auto-ignore stale entries written by older versions. [PR #693](https://github.com/Dstack-TEE/dstack/pull/693) bumps it from 2 to 3. No manual cache wipe required.

### R5. Contract whitelist

Each new KMS image hash must be whitelisted on the `DstackKms` contract before clients trust the new source. Tracked independently of the verifier upgrade.

## 9. Reference

Code locations:

- `dstack-mr/src/lib.rs:29` — `ovmf_variant_for_version`: OS version → OVMF variant.
- `dstack-mr/src/lib.rs:61` — `extract_version_from_image_name`: image-name fallback that [PR #693](https://github.com/Dstack-TEE/dstack/pull/693) sidesteps.
- `dstack-mr/src/acpi.rs:36` — `dstack-acpi-tables` subprocess invocation.
- `verifier/src/verification.rs` — `compute_measurement_details`: OVMF variant resolution chain.
- `vmm/src/app.rs` — `make_vm_config`: where the VMM populates `ovmf_variant`.
- `kms/dstack-app/builder/Dockerfile` — `QEMU_REV` pin and `dstack-acpi-tables` build instructions.

External:

- [`kvinwang/qemu-tdx`](https://github.com/kvinwang/qemu-tdx) — upstream of `dstack-acpi-tables` (patched QEMU with `-DDUMP_ACPI_TABLES`).

Releases and PRs:

- `kms-v0.5.11` (commit `40eaf35e`): first KMS release with OvmfVariant dispatch.
- [PR #678](https://github.com/Dstack-TEE/dstack/pull/678) — `fix/dstack-mr-ovmf-202505-events`, the kms-v0.5.11 fix series.
- [PR #693](https://github.com/Dstack-TEE/dstack/pull/693) — `metadata.json.version` resolution fix described in [verifier capability by KMS release](#5-verifier-capability-by-kms-release).
- [PR #679](https://github.com/Dstack-TEE/dstack/pull/679) — `dstack-mr diagnose` subcommand used in [pre-flight verification](#7-pre-flight-verification-with-dstack-mr-diagnose).

Related documentation:

- [Verification overview](../verification.md) — top-level intro to dstack attestation and tools.
- [Attestation Verification tutorial](../tutorials/attestation-verification.md) — MRTD/RTMR0-3 walkthrough, full `dstack-mr` build from source, RA-TLS, RTMR3 event log replay.
- [KMS build configuration](../tutorials/kms-build-configuration.md) — how the `dstack-kms` Docker image is assembled, including the embedded `dstack-acpi-tables`.
