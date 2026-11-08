<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-int-compatibil-008"></a>
# TC-INT-COMPATIBIL-008: In-place app OS upgrade after KMS root rotation

## Objective

Verify the complete physical-TDX migration path for an application that already owns a persistent encrypted disk:

1. Boot the app with the old KMS and old OS.
2. Onboard the replacement KMS and complete root-key handover.
3. Activate a new root epoch and retain the old epoch.
4. Stop the same app VM while retaining its data disk and identity.
5. Upgrade the app in place to the new OS image.
6. Boot the new OS, read the old disk epoch, fetch the authorized historical key, migrate the LUKS key and epoch token, and continue boot.
7. Verify the app starts with the same app identity and data, while new environment encryption uses the active epoch.

The test must use a real TDX guest and a lease-owned KMS/VMM/Gateway topology. Unit tests and simulator runs do not satisfy this case.

## Required scenarios

### Successful migration

The old OS boots and writes a sentinel to the encrypted data disk. After KMS onboarding and root rotation, the new OS starts from the same VM/workdir and disk. It must migrate the disk key atomically, rewrite the epoch metadata, unlock the disk, and expose the sentinel.

### Interrupted migration

Interrupt the migration after temporary-header validation and before final header replacement. Restart the new OS. It must either complete safely from the preserved source header or recover the original disk without data loss; it must never leave a partially accepted header.

### Historical and future epochs

A disk tagged with a retained historical epoch is migrated only after explicit authorization. A disk tagged with an unregistered or future epoch is rejected before data access and before destructive header changes.

### App epoch separation

Rotate the app epoch independently from the root epoch. Existing disk migration must use the root epoch, while new SealedEnv ciphertext binds both the active root and app epochs. A mismatched app epoch must fail closed.

### Rollback and old-client compatibility

Before guest migration, old OS clients remain usable at epoch zero. After migration, the old OS must not silently open the migrated disk with stale keys. A failed KMS handover must leave the source KMS, disk header, and app identity unchanged.

## Evidence

Record redacted root/app epoch numbers, public-key fingerprints, disk-header token fingerprints, app identity, data sentinel hash, KMS handover state, VM identity, boot status, and migration outcome. Never retain private keys, plaintext environment values, or reusable credentials.
