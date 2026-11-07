# AMD SEV-SNP hardware key provider plan

Status: provider implemented, updated 2026-11-07. Native SNP KMS boot and
fresh-launch recovery are validated. Host reboot and firmware-update tests are
pending; native TDX sealing is deferred.

A `snp` hardware key provider lets an AMD CVM run dstack KMS with
persistent local state. The deployment follows the existing SGX-backed model:

- The KMS CVM selects `key_provider: snp` and recovers its local disk key from
  AMD hardware on each boot.
- Application CVMs continue selecting `key_provider: kms` and consume the KMS
  through the existing protocol.

Protect KMS root and local sealing keys under the existing KMS isolation and
authorization model. Authorized applications retain their app-specific key
access. KMS service logic and application CVM protocols remain unchanged;
shared provider types require rebuilding affected binaries, including older
strict attestation verifiers that do not recognize `snp`.

## Findings that determine scope

A disposable Phala Cloud SNP CVM passed `SNP_GET_DERIVED_KEY` with explicit
VCEK selection using its existing guest kernel. Repeated requests returned the
same key. A Cloud restart replaced QEMU and changed both guest boot ID and SNP
report ID; the original key was recovered with unchanged measurement,
HOST_DATA, and persisted derivation TCB. Only key fingerprints were logged.
Changing the compose configuration changed HOST_DATA and the key while leaving
measurement and derivation TCB unchanged. Restoring the original configuration
recovered the original key.

The test used the [dstack dev box](https://github.com/Dstack-TEE/dstack-examples/tree/main/dev-box)
for guest access and required no host or guest kernel changes.

[Intel TDX module 2.0.18](https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_2.0.18)
implements `TDG.MR.KEY.GET`. Our DGX B300 EFI probe bypassed guest Linux and
measured `HW_SEALING=0`; enabling hardware keys and deriving a key both failed.
Testing newer Linux-loaded microcode did not enable sealing. Rollback was
verified.

Keep SGX for existing TDX KMS deployments. Consider a native TDX provider later,
after a platform reports `HW_SEALING=1` and passes derivation, fresh-launch
recovery, and policy-isolation tests. Module version alone is insufficient.
Add guest-kernel access and reuse the provider boundary then.

Tinfoil's public [keyserver](https://github.com/tinfoilsh/keyserver) releases
secrets from external stores. It does not establish native SNP sealing support.

## 1. Implement hardware derivation

Add a typed `SNP_GET_DERIVED_KEY` wrapper beside the existing
[`sev-snp-attest`](../dstack/sev-snp-attest/src/lib.rs) guest support. Extend
the pinned `sev` API or implement the documented Linux ABI directly; its
existing Boolean constructor cannot express explicit VCEK selection.

The hardware probe passed repeated derivation and fresh CVM relaunch with the
policy below. Implement this policy in the provider before KMS recovery tests.

Use a fixed sealing policy:

| Parameter | Value |
| --- | --- |
| Root | Explicit legacy VCEK: `ROOT_KEY_SELECT = 0`, `KEY_SEL = 1`; packed Linux `root_key_select = 2` |
| Guest fields | `0x29`: measurement, guest policy, and TCB version |
| VMPL | `0`, matching the guest |
| TCB | Supported initial derivation TCB, persisted and reused |

HOST_DATA and launch identity are also derivation inputs. Preserve the original
MrConfig document and instance metadata across restarts, as with the SGX local
provider. Store versioned public derivation parameters before disk unlock and
validate them against the fixed policy. Derivation or unlock failure must stop
startup.

Check both ioctl and firmware response status. Keep raw keys out of logs and
public APIs. Check firmware support for explicit root selection; do not
substitute another root or ephemeral keys.

## 2. Integrate it as another provider

Add `Snp` to [shared provider types](../dstack/dstack-types/src/lib.rs),
configuration schema, metadata encoding, and verifier mappings. Update VMM,
CLI, installer, and UI provider selection.

In [guest boot](../dstack/dstack-util/src/system_setup.rs), derive the local
seed directly inside the SNP guest and pass it through the existing
`gen_app_keys_from_seed` path before unlocking the data disk. Reuse the current
disk encryption and app-key derivation behavior.

Verify the existing HOST_DATA binding against the configuration observed by the
guest. Keep the provider identity independent of derived keys, since it enters
HOST_DATA before derivation.

## 3. Deploy KMS with the new provider

Select `snp` in the AMD KMS deployment configuration. Update its expected
measurements and provider metadata in the existing authorization policy.

Use existing KMS bootstrap, persisted root files, and onboarding. Configure the
existing SNP key-release gate for authorized SNP recipients. Application CVMs
continue using `kms`; no customer-held recovery key is introduced.

OS or compose changes require a new local sealing context. Use the existing
KMS onboarding/replication mechanism to preserve roots across those changes or
replacement hardware, as with the SGX local provider.

## 4. Validate provider equivalence

Add focused tests for the ABI, fixed derivation policy, provider selection, and
configuration binding. On real SNP hardware, verify:

- Repeated derivation, QEMU relaunch, and physical-host reboot recover the same
  local keys with the original launch inputs.
- The KMS restores the same CA and K256 public identities and existing disk
  data after restart.
- Existing application CVMs obtain the same app-specific keys through the KMS.
- Changed measurement, guest policy, HOST_DATA, or hardware cannot unlock the
  original disk. Include a malicious guest that copies the victim's HOST_DATA.
- A supported firmware update preserves recovery using the stored derivation
  TCB while attestation continues satisfying existing policy.
- Missing or incompatible derivation parameters fail without selecting a new
  key. Existing KMS onboarding still works with the new provider metadata.

Update [AMD deployment documentation](amd-sev-snp.md) with provider selection,
metadata preservation, and the validated hardware requirements.

Implementation validation passed 438 unit tests, Clippy, documentation hooks,
and the VMM UI build. An isolated SNP VM selected `snp` with SGX provisioning
disabled and no external KMS URLs. A fresh QEMU launch recovered the same disk
key, native CA, KMS CA and K256 identities, application keys through the existing
`GetAppKey` API, and persisted disk data. The KMS retained self-authorization.

Removing sealing metadata or changing HOST_DATA stopped boot without
reformatting the disk. Restoring the original inputs recovered all identities
and data. Only fingerprints were recorded; existing deployments were untouched.

Physical-host reboot and firmware-update tests still require a maintenance
window. Cross-hardware recovery, onboarding/replication, and the malicious
guest copying the victim's HOST_DATA remain separate validation work.

References: [AMD firmware ABI, section 7.2](https://docs.amd.com/v/u/en-US/56860_PUB_SEV_SNP)
and [Linux SNP guest API](https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html#snp-get-derived-key).
