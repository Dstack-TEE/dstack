<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# Key rotation models

TLA+ models of the [KMS key rotation protocol](../../kms-emergency-key-rotation-protocol.md)
as implemented, checked exhaustively with TLC within the stated bounds.

| Model | Covers | Implementation |
| --- | --- | --- |
| `KmsRotation.tla` | Root epoch registry, KMS keyrings, onboarding, key release | `DstackKms.sol`, `kms/src/main_service.rs`, `kms/src/onboard_service.rs` |
| `DiskMigration.tla` | Data disk setup and LUKS keyslot migration, with crashes | `dstack-util/src/system_setup.rs`, `system_setup/luks.rs` |
| `EnvUpdate.tla` | Env re-encryption at boot and the VMM update window | `dstack-util/src/system_setup.rs`, `vmm/src/app.rs` |

## Running

```bash
java -cp tla2tools.jar tlc2.TLC -config DiskMigration.cfg DiskMigration.tla
```

| Config | Bounds | Result |
| --- | --- | --- |
| `KmsRotation.cfg` | 3 nodes, 4 roots | `ReleasedFromRegisteredRoots` holds (4,525 states) |
| `KmsRotationHandover.cfg` | 3 nodes, 4 roots | `HandoverAgreesWithRegistry` violated |
| `DiskMigration.cfg` | epochs 0-2 | `NoBootFailure` violated |
| `DiskMigrationDataLoss.cfg` | epochs 0-2 | `DataRecoverable` violated |
| `DiskMigrationFixed.cfg` | epochs 0-2 | all invariants hold (1,326 states); also with epochs 0-4 |
| `EnvUpdate.cfg` | epochs 0-2, 2 owner updates | `OwnerUpdateKept` and `NoAppEnv` hold |
| `EnvUpdateLossy.cfg` | same, lossy notifications | `NoAppEnv` violated |

Checked with TLC 1.8.0 on OpenJDK 21. `KmsRotation` safety also holds with 4
nodes and 5 roots (59,187 states).

## Findings

**A crash during disk key migration can destroy the volume key.**
`luksChangeKey` moves keyslot 0 to the other keyslot area, and
`luksHeaderRestore` writes both header copies and both areas in one 16 MiB
write. If a crash leaves a new header copy on disk before the new keyslot area,
neither key opens the disk; cryptsetup then rewrites the outdated copy from the
newer one on the next access, so the old keyslot is lost for good
(`cryptsetup-torn-restore.sh`). The boot that ran the migration still succeeds,
because it opens the volume from the in-memory copy.

**An interrupted initialization fails every later boot.** `luks_setup` formats
the disk and imports the epoch token in two steps. A crash between them at a
nonzero epoch leaves a disk keyed for the current epoch whose header records
epoch 0, so the next boot migrates from epoch 0, fails, and never reaches the
reinitialization of interrupted disks.

`DiskMigrationFixed.cfg` checks a fix for both: run `luksChangeKey` on the
device, whose writes are ordered and synced (new area, primary, secondary, old
area; measured with strace), then import the token, and on boot open the disk
with the first epoch from the recorded one to the current one whose key
unlocks it. Trying only the recorded and current epochs is not enough: a crash
between the key change and the token import, followed by another rotation,
leaves a key of an intermediate epoch.

**Application code can replace the env if both boot notifications fail.** The
VMM closes the update window on the guest's first update or on boot progress
reaching application code. Both are best-effort (`update_sealed_env` and
`notify-host ... || true` failures are only logged), so if both are lost, an
init script or container that can reach the host API can store an env of its
choosing. Owner updates are never overwritten in either case.

**An ordinary join can hand over a losing root.** Two rotation joins can
generate competing roots for the same pending epoch. After the owner registers
one, a node holding the other still serves the current epoch, passes the export
and import checks (the recipient checks the chain hash only up to the current
epoch), and hands its root on. The recipient cannot serve once the epoch is
activated. Released keys are unaffected: `ReleasedFromRegisteredRoots` holds.

## Abstractions

- A key epoch in `DiskMigration` and `EnvUpdate` stands for the (root, app)
  epoch pair; the KMS serves every epoch up to the current one.
- Roots are unique values; chain hash comparison is prefix equality. With unique
  roots, checking only the current root would be equally safe; the full chain
  hash check is defense in depth.
- The owner registers what a generating node attests and activates an epoch once
  some node can serve it. Governance and attestation are trusted.
- Rotation happens while CVMs are stopped, as the runbook requires.
- `WriteToken` and the device-side `luksChangeKey` steps are atomic per header
  copy; cryptsetup syncs each copy and repairs an outdated one on load.
