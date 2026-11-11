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
| `DiskMigration.tla` | Data disk setup and LUKS key migration, with crashes and rotations | `dstack-util/src/system_setup.rs`, `system_setup/luks.rs` |
| `EnvUpdate.tla` | Env re-encryption at boot and the VMM update window | `dstack-util/src/system_setup.rs`, `vmm/src/app.rs` |
| `EpochPolicy.tla` | Root and app epoch policy rows, range setters, pop and re-registration, legacy app policies, key release on the selected rows | `DstackKms.sol`, `DstackApp.sol` |

## Running

```bash
java -cp tla2tools.jar tlc2.TLC -config DiskMigration.cfg DiskMigration.tla
```

| Config | Bounds | Result |
| --- | --- | --- |
| `KmsRotation.cfg` | 3 nodes, 4 roots | `ReleasedFromRegisteredRoots` and `HandoverAgreesWithRegistry` hold (4,423 states); also with 4 nodes, 5 roots (57,889 states) |
| `DiskMigration.cfg` | epochs 0-3 | all invariants hold (828 states) |
| `EnvUpdate.cfg` | epochs 0-2, 2 owner updates, lossy host API, fail-closed guest | `OwnerUpdateKept` and `NoAppEnv` hold (267 states) |
| `EnvUpdateLossy.cfg` | same, guest only logs an unanswered update | `NoAppEnv` violated |
| `EpochPolicy.cfg` | root epochs 0-2, 5 registrations, 2 choices of keys, 2 values; app epochs 0-2, 1 compose hash | `RevocationIsTotal`, `AppKeyMatchesSelectedRow` and `RegistrationStartsEmpty` hold (6,104,564 states) |
| `EpochPolicyChainHash.cfg` | same, rows keyed by chain hash | `RevocationIsTotal` violated |
| `EpochPolicyLegacyAppEpoch.cfg` | same, legacy app fallback ignores the requested app epoch | `AppKeyMatchesSelectedRow` violated |

Checked with TLC 2026.11.06 on OpenJDK 21. `EnvUpdate.cfg` models the guest of
#1546; `EnvUpdateLossy.cfg` the guest before it.

Each model was checked against mutations of the implementation, each of which
produces a counterexample:

- `DiskMigration`: requiring a single keyslot when the current key unlocks none
  (a migration interrupted before a later rotation then fails every boot);
  opening without removing the old keyslot; treating a disk that still carries
  the initializing label as initialized.
- `KmsRotation`: skipping the latest registered epoch's chain hash check on
  handover, which lets an ordinary join pass on a losing pending root.
- `EnvUpdate`: starting applications after an unanswered update.
- `EpochPolicy`: the two configs above; and treating a removal from the
  current epoch through the latest as a revocation, as the epoch-less setters
  before #1561 did, which lets a historical row still release the key.

## Abstractions

- A key epoch in `DiskMigration` and `EnvUpdate` stands for the (root, app)
  epoch pair; the KMS serves every epoch up to the current one. Authorization
  is assumed to allow the instance at each of them; `EpochPolicy` models the
  rows that decide it, and a migrating instance must be allowed in the old
  rows too.
- In `KmsRotation`, keys are released for epochs up to the current one and
  handed over up to the latest registered one, the operation bounds of
  `kms_serve`/`app_get_key` and `kms_export_keys`/`kms_import_keys`.
- `EpochPolicy` merges the root materials (OS image, KMS MR and device) into
  one row per epoch, and the app materials into compose hashes; a release
  needs one allowed value in each selected row. It has one app and no KMS
  nodes; `KmsRotation` covers the keyrings.
- A boot fetches its keys once; the KMS may rotate at any point of
  `DiskMigration`, and between boots in `EnvUpdate`.
- Each cryptsetup command on the device is atomic: it writes a new keyslot
  area before the header copies, syncs each, and repairs an outdated copy on
  the next load. A crash may stop a boot between any two commands.
- Roots are unique values; chain hash comparison is prefix equality.
- The owner registers what a generating node attests and activates an epoch once
  some node can serve it. Governance and attestation are trusted.
- `EnvUpdate` does not model a VMM without `UpdateSealedEnv`, which has no
  update window.
