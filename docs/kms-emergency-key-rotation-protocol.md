# KMS emergency key rotation protocol

**Status:** Design draft; not implemented. Proposed fields require protobuf definitions.

## 1. Scope and assumptions

- Threat model: KMS root private keys are exposed, while disk data, LUKS headers,
  and provider/host access are not. Repair the KMS environment before rotation.
- Stop all application CVMs and gateways; upgrade their OS and restart together.
- Reuse DstackKms governance and its OS allowlist. Assume configured chain RPCs
  are trusted; RPC rollback and malicious-host/data anti-rollback are out of scope.
- Keep existing root-public-key pins. Affected deployments are handled separately.
- Rotate LUKS keyslots only; the underlying volume key remains unchanged.
- Every current KMS stores and hands over the complete root history, epochs 0..N.
- KMS stores no individual migration progress. No JWT, live rotation, or gateway
  admission-lease protocol is introduced.

**Storage boundary:** old root + old LUKS header reveals the unchanged volume
key. If ciphertext is later exposed, this can affect post-rotation data too.
Treat historical headers/snapshots as sensitive and inventory/isolate/dispose of
copies operationally. Full reencryption is future work if host/storage exposure
enters the threat model; slot replacement is not equivalent protection.

## 2. Behavior summary

Historical GetAppKey requests return complete epoch material and stay available
without a deadline, so late or restored instances can still migrate. Automatic recovery covers
disk keyslots and environment ciphertext with cloud-platform assistance;
application-owned GetKey data and wallets remain application responsibilities.
Onboarding supports ordinary full-history import and rotation import followed
by local generation of the next epoch. Sections 6-7 specify these flows.

## 3. Roots, policy, and compatibility

`api_version` selects protocol behavior; `root_epoch` identifies root material.
Epoch 0 is the existing roots, with existing derivation formulas and outputs
unchanged. Every epoch selector is optional; unset means the current epoch.
The name leaves room for a separate per-app epoch later. Generate
independent fresh CA and secp256k1 roots for each new epoch; existing derivation
formulas can remain unchanged. Never reuse an epoch for different roots.

DstackKms keeps a registry of each epoch's root public keys, whose keys and
chain hash never change once registered (a pending epoch may be popped), an
`evidenceUrl` locating the attestation that proves where they were generated, and
a chain hash `h_n = keccak256(h_{n-1} || keccak256(caPubkey) || keccak256(k256Pubkey))`
(zero `h_{-1}`) committing to every key up to `n`; the position in the chain
fixes `n`, and hashing each key first keeps the preimage fixed-length. The
contract accepts only the encodings the KMS produces: a 91-byte P-256 DER
SubjectPublicKeyInfo with an uncompressed point, and a 33-byte compressed
secp256k1 key, so one key cannot be registered under two encodings. The
evidence stays off chain (stored on chain it would cost about 720 gas per byte)
and needs no hash: its report data binds the keys, so only availability depends
on the URL, which the owner can update (`setRootEpochEvidenceUrl`) when the
evidence moves. Registering an epoch and
making it current are separate: `registerRootEpoch` appends (epoch 0 becomes
current at once) and `activateRootEpoch(n)` moves the current epoch forward one
step. `popRootEpoch(n, chainHash)` drops the last epoch while it is still pending, for when
the nodes holding it are lost before activation; a re-rotation then registers a
new `n`, whose OS image, KMS MR and device rows start empty because policy rows
are keyed by the epoch's chain hash. Prepare them again before activating. A
current epoch is never popped. `kmsInfo` follows the current epoch:
registering epoch 0 and each activation copy its keys there and clear the legacy
quote and event log, and `setKmsInfo` is refused once epochs exist. Epoch 0 must be the `kmsInfo` keys
when those are set; a legacy `kmsInfo` quote and event log are converted off
chain into the standard attestation encoding (`Attestation::from_tdx_quote`)
before publishing. The KMS sends the epoch it serves and its chain hash (`rootEpoch`,
`rootEpochHash`) in every boot check, and the auth backend owns the policy: it
denies a KMS that does not serve the current epoch with the registered keys.
Info responses report the current epoch for KMS startup and onboarding; boot
responses are unchanged, and so is the on-chain `AppBootInfo`.
Governance credentials must remain independent and uncompromised.

The KMS keyring and backups contain every epoch the node holds, not just the
latest two. Keeping old roots does not authorize issuing old derived keys. There
is no local epoch configuration: a KMS serves the current epoch on chain,
provided its keyring holds it and reproduces its chain hash, and waits
otherwise. When the current epoch moves, the KMS restarts to follow it and
re-signs its RPC certificate under the new root CA. A `root-epoch` marker records
the newest stored epoch.

Historical epochs are not time-limited. Their roots are already exposed, so
withholding derived keys from authorized CVMs would not reduce what an attacker
can derive, while it would strand instances or backups that miss a deadline.
Old OS images are cut off through the OS allowlist instead. If host-side disk
rollback enters the threat model, a release deadline can be added later.

Compatibility: keep accepting GetAppKey versions 0/1. An absent selector means
the current epoch, which before any rotation is epoch 0, so old OS images see no
change. After rotation they cannot open migrated disks; remove old OS images
through the existing allowlist and retain OS-image verification. Historical
epoch access never overrides OS/application authorization.

## 4. GetAppKey additive extension

Reuse the existing [GetAppKey transport and authorization path](../dstack/kms/src/main_service.rs),
without claiming a new KMS measurement-allowlist check on the guest. Preserve
root-public-key checking through `key_provider_id`; there is no separate guest
epoch pin or chain query. Unpinned deployments retain their existing KMS identity
limitations: this proposal does not create independent replacement-root trust
for them. Changing a pin can change compose/config hashes and related allowlists
or verifier expectations; affected deployments need separate coordinated updates.

Keep `api_version = 1`; add one epoch selector:

```protobuf
message GetAppKeyRequest {
  uint32 api_version = 1;
  string vm_config = 2;
  // Unset = the current epoch, N = epoch N.
  optional uint32 root_epoch = 3;
}
// Add to AppKeyResponse; preserve fields 1-8 and their types.
uint32 root_epoch = 9;
```

Unset resolves to current once for this request; unknown epochs are rejected.
Response `root_epoch` and all epoch-dependent material in fields 1-8 belong to
the resolved epoch. There is no separate source disk field. Every epoch up to
current uses the same normal authorization. A guest asks for an older epoch by
number only when it needs one, so a boot with nothing to migrate makes a single
request.

An allowed historical request returns the complete historical AppKeyResponse,
including env and application keys, to preserve legacy compatibility. This
replaces the earlier disk-only server response proposal: the new OS extracts
only disk_crypt_key and, when needed, env_crypt_key for migration, discarding
other historical material. It retains its latest bundle for app startup. This
accepted tradeoff restricts recipients, not cryptographic uses of returned keys.

The guest checks explicit epoch responses against the requested number. An old
KMS ignores the selector and serves epoch 0, reporting 0; that is
indistinguishable from a not-yet-rotated KMS using these fields alone.
Existing root-public-key pins and removal of old KMS endpoints remain essential;
unpinned clients gain no new downgrade protection. Do not rely on cached/disabled
KMS self-authorization for immediate revocation. Test JSON compatibility separately.

Authenticate the KMS connection against current configured trust. Historical
ca_cert in the response is historical data, not a replacement transport trust
anchor: do not install it or compare it as though it were the current server pin.

## 5. OS slot migration and LUKS header metadata

Store the epochs in one LUKS2 JSON token bound to the keyslot holding their key:

```json
{"type":"dstack-kms","keyslots":["0"],"root_epoch":2,"app_epoch":0}
```

The validator rejects nonzero subsystem, unexpected labels, and any token but
this one. It accepts keyslot 0, keyslot 1, or both (only mid-migration), each
with the same pinned parameters, and requires both header copies to agree.
Disks without the token are epoch 0. Requires cryptsetup 2.5 or later
(`--token-replace`, `--new-key-slot`); Debian trixie ships 2.7.

```text
copy the header to tmpfs -> validate the copy
  initialization label set -> reformat (the disk holds no data yet)
  token_or_0 > current -> refuse
  current key unlocks a keyslot of the copy -> finish
  otherwise, token_or_0 < current -> old keys of epoch token_or_0
          -> check they unlock the recorded slot (token slot, else slot 0)
          -> luksKillSlot any other slot
          -> luksAddKey (old key authorizes the new key in the free slot)
          -> recopy and validate -> finish
  finish: token import (current epochs, surviving slot) -> luksKillSlot others
          -> recopy, validate, and check the result -> open with the copy
```

Each step is one LUKS2 metadata commit, which cryptsetup keeps crash-consistent
across both header copies. Whatever step a crash interrupts, the next boot
finds either the old key alone or a keyslot the current key already unlocks,
so trying the current key first resumes the migration. If another rotation
happens before that boot, the current key unlocks neither of the two keyslots
an interrupted migration leaves; the token still names the slot of the recorded
epochs, so the other slot is dropped, but only once the recorded epochs' key is
confirmed to unlock that slot, and the migration restarts from it. A crash between
`luksFormat` and the token import leaves the initialization label set, which is
cleared only after the filesystem exists, so such a disk is reformatted. Never
format on unlock failure. Invalid or unsupported metadata requires recovery.
The disk is opened only with the last validated in-memory copy.

No extra reboot is required. Historical material is confined to the migration
step, not persisted or passed to applications.
Old OS implementations with the existing validator reject a token-bearing disk;
this is an additional defense, not a substitute for the OS allowlist. Because of
that, an epoch-0 disk is never tagged: before any rotation the new OS leaves the
header untouched, so rolling back to an older OS image still works. Disks
formatted at a later epoch are tagged immediately.

Tested in a Debian trixie container (cryptsetup 2.7.5, 32 MiB file images,
LUKS2/PBKDF2, no dm mapping): full migrations, resumption after each step,
disagreeing header copies, failed `luksAddKey` or denied old epochs leaving the
old epochs in place, failed token import, and disks recording newer epochs.
Old key-area wiping remains a release blocker.

## 6. Environment migration, application keys, and TLS

First decrypt env using latest. On authentication failure, try historical keys
from current down to 0, at most once each per boot; no platform metadata is
required. Skip an epoch whose key the KMS refuses, or that does not decrypt, until
one does: each historical key is still authorized by the KMS, and stopping at a
refusal would strand env encrypted under an older epoch whose image is approved
there but not in a newer row. The search costs at most current+1 RA-TLS requests,
only until the env has been migrated. Ciphertext no key decrypts fails closed;
env epoch is independent of the disk token. Empty env requires no migration.

Decrypt/re-encrypt only inside the CVM, using current env public key, existing
format, and fresh randomness. The guest does not read the replacement back:
sealing and opening are deterministic code, so integration tests guarantee that
a re-sealed env opens on the next boot, after the VMM has replaced the old one.
The guest pushes the result to the VMM with `HostApi.UpdateEncryptedEnv` on
every boot, before any application code runs, sending an empty env when nothing
changed. The host API is reached over the VM's own vsock, so the VMM knows which
VM sent it. The VMM records the env each boot starts with and accepts one update
per boot, only until the boot reports init scripts or containers starting, and
only if the stored env is still the boot env, so an owner's concurrent update is
never overwritten. Application containers and scripts therefore cannot replace
the env. Rocket's per-method limit bounds the request (1 MiB by default). A
missed update is retried on the next boot. Plaintext and private keys never
leave the CVM.

`GetAppEnvEncryptPubKey` keeps its interface. It always derives and signs with
the current epoch's roots and never serves historical epochs: env public keys
encrypt new data, so serving an older epoch would encrypt new secrets to a leaked
key. The signer public key identifies the epoch; no response field is added.
SDKs/frontends refresh cached env public keys before uploads; old-key uploads
are still migrated at boot, but put new secrets under an exposed key. Prompt owners to replace exposed
external credentials: reencryption alone does not revoke passwords/tokens.

Guest API v1 `GetKey` takes an optional `root_epoch` (unset = current) and reports the epoch it
derived from; the SDKs expose it as an optional argument. The default is the
current epoch so new keys never come from an exposed root by accident. GetKey
outputs therefore change after a rotation: owners migrate app-encrypted records,
signing trust, wallets, and permissions by reading old keys with an explicit
`root_epoch` before releasing business services. The guest agent fetches an
older epoch's app root from the KMS the first time GetKey names it and keeps it
in memory; old roots are not stored in the keys file. The frozen v0 surface
always uses the current epoch. A per-app epoch, if added later, follows the same convention. SignCert
retains existing checks and signs under current roots; GetMeta is not a trust
anchor. Change CVM/gateway certificate trust in both directions. Public ACME
certificates remain separate. Orchestration gates all business activity, including
outbound workers, until readiness.

## 7. Full-history KMS onboarding

Onboarding imports the source's whole keyring, 0..S, and checks it against the
recipient's `authorizeKms` result: the current epoch's chain hash, and the latest
registered epoch L (`latestRootEpoch`, `latestRootEpochHash`). It never selects a
subset. A source holding epochs beyond L is refused ("source KMS holds
unregistered root epochs"). When S = L, the chain hash of L must match; chain
hashes are cumulative, so this binds the whole pending tail, not only the current
prefix. A source holding exactly the current epoch still joins; one stopping
between the current epoch and L is refused, since its tail cannot be checked. With
`rotate`, it then generates epoch S+1.

| Mode | Source requirement | Result |
| --- | --- | --- |
| Ordinary join | Holds the current epoch and nothing unregistered; a registered tail pending activation must match the latest chain hash | Keyring 0..S |
| Rotation join (`rotate=true`) | Holds exactly up to the current epoch, with no epoch registered beyond it | Keyring 0..S plus fresh epoch S+1 and attestation evidence |

Every handover requires the recipient's KMS attestation: the source checks the
attested RA-TLS client certificate on both `Admin.GetKmsKey` and the public
`KMS.GetKmsKey`. Admin authorization (`source_token`) is recommended for joins
and rotations alike, but not required: a rotation only produces a pending epoch
N+1, which no node accepts until governance registers and activates it. Where
possible, disable public legacy handover and reject incompatible legacy
receivers without reducing the payload. The source's certificate must carry its
OS image hash.
Deployments that never registered epochs can still join at epoch 0.

For rotation, generate fresh roots and attest them with the bootstrap encoding
used for every epoch: report data is
`keccak256("dstack-kms-genereted-keys-v1:{ca_pubkey_hex};{k256_pubkey_hex};")`
zero-padded to 64 bytes. The "genereted" spelling is part of the released format.
The evidence only has to prove the key pair was generated in an approved TEE.
It binds neither the epoch number, which comes from the on-chain registration
order, nor the preceding chain hash, which joins already check against the
registry; a mismatch in either is an availability problem that `servable_epoch`
catches at once, not a key leak. Before registering N, the owner verifies the
quote with dstack-verifier, checks the approved code and measurements, and
recomputes the report data from the published keys; the cluster keeps
serving N-1. After the other nodes onboard and hold N, the owner activates N and
every KMS restarts onto it. An old-root signature is not authorization.
Competing generators cannot both be registered as N; a losing node's keyring no
longer reproduces the chain hash, so it never serves and must onboard again. It
also cannot hand its N over: joining from it fails the latest-epoch check while N
is pending, so the wrong tail does not reach later joiners.

Every authorization request (app checks and the KMS self check that gates all
RPCs) carries the epoch the KMS serves, so a backend refuses a stale or forked
KMS. On a denial the KMS reads the current epoch from the info endpoint and
restarts if it moved. A KMS predating root epochs sends none; backends treat it
as epoch 0 and, once a later epoch is current, deny both its self check and its
app checks, so old KMS software stops serving. The contract's legacy
`isKmsAllowed` and `isAppAllowed` refuse as well, so this cutoff does not depend
on the backend. Upgrade every KMS before
activating a new epoch. In-flight operations are not cancelled.

Backups retain full history; closing migration does not delete roots. Replacement
KMS boot cannot depend on its own unavailable service or stopped gateway ingress.
Protect root storage and independent admin access.

## 8. Cutover runbook

1. Inventory app/key dependencies, env ciphertext, pins, and historical snapshots.
   Prepare trusted OS images, application recovery, and provider-pin adjustments.
2. Stop business writes, CVMs, gateways, and compromised KMS paths. Repair/replace
   KMS execution and rotate independently exposed admin credentials.
3. Rotation-onboard one node, register its new epoch, then ordinary-onboard peers.
   Authorize new KMS images before removing old OS images; do not rotate again
   during the cutover.
4. Boot new OS with business services held by orchestration. Migrate slots and
   complete platform env replacement; confirm app readiness. Ingress closure alone does
   not stop workers, cron jobs, queues, or outbound database/wallet writes.
5. Start gateways with fresh data directories/KV namespaces and clean WireGuard
   peers. Rebuild required non-admission configuration from trusted sources;
   never restore old registration databases or admit old sync nodes.
6. Re-register CVMs with new certificates and release approved business
   services/ingress. Keep failed instances isolated for operator follow-up.
7. Notify env public-key verifiers (vmm-cli signer whitelists, frontends, SDK
   callers) to replace the old k256 signer with the new one, preferably by reading
   it from DstackKms. For vmm-cli, run `kms remove <old signer>`, then
   `kms add <new signer>`. A stale whitelist entry does not break migration, but
   lets anyone holding the old root and able to intercept client-to-KMS traffic
   forge env public keys; the `root_epoch` in a response is set by its signer
   and protects nothing.

## 9. Invariants and acceptance

Authenticate actual secret-bearing connections; old-CA signatures alone do not
replace evidence checks. Do not downgrade on failure or expose secrets in logs,
command lines, swap, app key files, or host-shared storage. Released secrets
cannot be recalled. Historical key possession,
current unlock success, and production readiness are three different facts.

Test legacy compatibility, OS-allowlist cutoff, selector boundaries and epoch-0 compatibility, non-adjacent epochs,
both onboarding modes, full-history atomic persistence, pending registration
restart, competing roots, live stale-node rejection, and epoch mismatch, slot/token crash recovery,
new-key reboot success, old-key unlock failure against the working header, and
absence of residual old paths and recovery from missing/stale epoch tokens. Confirm the volume key intentionally stays the
same. Test env corruption, independent env epochs, concurrent platform updates,
response-source authentication, bounded epoch search, stale-key uploads,
replacement/reboot recovery, application readiness,
and clean gateway reauthentication/sync.
Reports must state OS/TEE, kernel/cryptsetup, filesystem/layout, builds, topology,
policy, and failure injections. The preliminary test above is limited evidence, not release validation.
