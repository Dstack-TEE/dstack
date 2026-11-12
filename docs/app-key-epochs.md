# Application key epochs

Application owners can rotate their app's derived keys without rotating KMS root
keys or other apps. This extends SealedEnv (#1528); the PR dependency order is
#1519 → #1517 → #1520 → #1521 → #1528 → application epochs.

## Authorization and rotation

`authorizeApp` returns `currentAppEpoch` together with the current root
epoch and its chain hash. `requestedRootEpoch` and `requestedAppEpoch` are
independent `OptionalUint256` values: omitted selects current, explicit zero selects
historical epoch zero. Future epochs are denied through `rejectionReason`.
`authorizeKms` remains separate and uses app epoch zero.

`DstackApp.currentAppEpoch` starts at zero. Its owner calls
`advanceAppEpoch(expectedCurrentEpoch)` to increment it. The expected value
prevents a stale or retried transaction from advancing twice. Epochs cannot be
rolled back and are limited to uint32. Prepare the next row before advancing, as
with a pending root epoch: approve its materials with `*AtEpoch(N + 1, ...)`,
then call `advanceAppEpoch(N)`, so guests that restart after the advance are
authorized at once. `AdvanceAppEpoch` in `Manage.s.sol` exposes
this operation; `GetAppEpoch` in `Query.s.sol` reads it. Upgrade the app policy
implementation before advancing, and upgrade the KMS/auth backend and guests
before using nonzero epochs. Once the app epoch is nonzero, the legacy
`isAppAllowed` of both `DstackApp` and `DstackKms` refuses, since its callers
derive epoch-zero keys, so the KMS contract calling the app policy must support
epochs before the app epoch advances. The ERC-165 `IAppEpochAuth` capability combines
`currentAppEpoch()` and `authorizeApp(AuthorizationRequest)` in one interface; the
policy returns the same `AuthorizationResult` struct as `DstackKms`. The request
also carries `teeVariant`, the platform name the KMS reports, which
`allowAnyTeeVariant` and `allowedTeeVariants` in `DstackApp` and `DstackKms`
restrict to the platforms listed in `TeeVariantPolicy.sol`; listing a new
platform takes a contract upgrade. Like `allowAnyDevice`, the policy covers every
epoch: which platforms may hold an app's keys is a trust decision, not a property
of a key generation. Legacy policies
without this capability remain at zero; failures of an advertised getter propagate.

The Ethereum auth backends query the policy through the KMS contract. The simple
backend reads `apps[appId].currentAppEpoch` (default zero); operators must preserve
its monotonicity. Public encryption-key lookup uses `GET /app/:appId` to read this
value. Legacy boot authorization and legacy environment public-key issuance are
rejected once the app epoch is nonzero, preventing old clients from silently
continuing with epoch-zero keys.

## Epoch-scoped allowlists

Material approvals are an exact `epoch × material` matrix, not a maximum epoch.
Authorization checks only the selected row, with O(1) add, removal and lookup:

- `DstackKms`: OS images, KMS aggregated measurements and KMS device IDs are
  indexed by **root epoch**. OS image limits also apply to app key requests.
- `DstackApp`: compose hashes and device IDs are indexed by **app epoch**. Each
  required material must be allowed in the selected row. `allowAnyDevice` is a
  single switch over every app epoch: which hosts may run the app is not a
  property of a key generation, and a per-epoch switch could leave an older
  epoch open to any host after the current one is restricted.

There is no implicit access in either direction. Rotating keys starts an empty
row; approving a new row neither copies old approvals nor grants historical keys.
Root and app selectors remain independent. Omitted selectors select the current
epochs. For an image handover, explicitly approve the new image in the old row so
it can migrate old keys, approve it in the new row, and remove the old image from
the old row after the handover. The old image never needs access to the new row.

A request may select any epoch up to the current one and is decided on that
epoch's row, so a value is revoked only once every row allowing it is cleared.
Neither contract has epoch-less material setters:
`*AtEpochs(fromEpoch, toEpoch, material)` changes every row in the range, and in
`DstackApp` `*AtEpoch(epoch, material)` one row (in `DstackKms`, pass the epoch
twice). One transaction revokes a value from all rows, with
`remove*AtEpochs(0, latest, …)` in `DstackKms` and
`remove*AtEpochs(0, currentAppEpoch, …)` in `DstackApp`. `DstackKms` writes
registered root epochs (before any is registered, only epoch zero); `DstackApp`
writes app epochs up to the next one.
`DstackApp` reports these setters as the ERC-165 interface
`IAppEpochManagement` and no longer reports `IAppAuthBasicManagement`
(`0x8fd37527`), whose epoch-less setters it removed. The scripts in
`Manage.s.sol` take `ROOT_EPOCH` or `APP_EPOCH` for one row, or
`FROM_ROOT_EPOCH`/`TO_ROOT_EPOCH` and `FROM_APP_EPOCH`/`TO_APP_EPOCH` for a range,
and fail without them.

App policies deployed before app epochs (v0.5.x, v0.6.0) keep working with an
upgraded `DstackKms` and KMS: they report no `IAppEpochAuth`, so `authorizeApp`
asks their `isAppAllowed` and only for app epoch zero, and `currentAppEpoch`
reports zero for them. Their owners keep the epoch-less setters until they
upgrade, which `Manage.s.sol` detects and uses with no epoch or `APP_EPOCH=0`.
Upgrading keeps their allowlists as app epoch zero. See
[onchain-governance.md](./onchain-governance.md#apps-deployed-before-app-epochs).

Disk and environment migration after a root rotation fetches the keys of the
recorded epoch, so a new image migrating old data must be allowed in that old
row too. Without it the guest stops with an error naming the root and app epoch
it could not get keys for.

The `*AtEpoch` getters read the selected row, including legacy epoch zero.
`EpochPolicyChanged` events include the row and the resulting permission. Legacy
bool getters and events describe **epoch zero only**; changing a nonzero row does
not change its legacy bool or emit a misleading legacy material event. The
exception is `allowAnyDevice` and its `AllowAnyDeviceSet` event, which cover every
app epoch.
Root policy rows from epoch 1 belong to the epoch's registration, so a row can
be written only once the epoch is registered (register, prepare the row, then
activate). A popped epoch's rows do not carry over: the next registration of the
number starts with empty rows, even with the same keys, which must be prepared
again before activation. Epoch 0 keeps the legacy mappings.

### KMS keyring handover

Keyring handover is deliberately different from app key access: approval in the
**highest exported root epoch** authorizes the entire keyring, including all older
roots. The KMS passes that epoch explicitly to `authorizeKms`, so approval in the
current row cannot accidentally authorize a newer pending keyring. A registered
pending root may be authorized for KMS handover before activation; app key requests
still cannot select it. KMS self-authorization without a selector continues to
check the active root epoch. The source checks `kms_import_keys` for the recipient, and the recipient
checks `kms_export_keys` for the source, both at the highest transferred epoch.
This permits staged key distribution without changing which epoch the KMS serves.

### Upgrading existing proxies

The original bool mappings and `allowAnyDevice` retain their storage locations and
are used directly as row zero. New storage consumes storage-gap slots in each
contract (seven in `DstackKms`, four in `DstackApp`); no entries are copied and no reinitializer is required. Existing
owners, pending owners, policy flags, root registries and app epoch counters are
preserved. Even if the pre-upgrade counter is nonzero, old global material
approvals grant only row zero after upgrading: explicitly populate the intended
nonzero rows. `allowAnyDevice` keeps covering every app epoch.

Upgrade the KMS policy before app policies, then approve the intended rows before
restarting guests or activating a new root. `DstackApp` advertises the optional
ERC-165 `IAppEpochAuth` capability. `DstackKms.authorizeApp` first applies the
checks it owns (operation scope, registered root epoch, requested root epoch not
beyond the current one, app registration, OS image at the selected root epoch,
deployed contract), then forwards the request unchanged to the policy's
`authorizeApp`. The policy validates the operation and the requested app epoch and
fills `authorized`, `rejectionReason` and `currentAppEpoch`; the KMS then sets
`gatewayAppId` and the current and latest root epoch fields. The decision and
its app epoch therefore come from one policy call. Its interface ID is the XOR of
both method selectors; policies advertising only either former single-method
interface must upgrade to the combined interface. Policies without that capability can only
authorize app epoch zero; failures of an advertised method propagate instead of
falling back.
Direct legacy app checks use the current app epoch; legacy KMS app authorization
still rejects nonzero app epochs.

These material matrices are implemented by the Solidity policies. Config-file auth
backends such as dstack-auth retain their own policy model; dstack-auth applies the
same epoch limits, accepting a registered pending root epoch for KMS handover and
only active epochs for key-issuing operations.

## Derivation and lifetime

Every key is identified by `(root_epoch, app_epoch)`. App epoch zero keeps existing derived keys and app-key signatures. Nonzero app epochs append
`"app-epoch-v1:" || app_epoch[4, big-endian]` to the existing derivation context
for disk, environment, SealedEnv, app CA and secp256k1 keys.

The root signature for a nonzero app secp256k1 key signs Keccak256 of
`"dstack-kms-issued-v2:" || app_id[20] || app_epoch[4, big-endian] || public_key[33]`.
Relying parties must verify this format against the trusted root key for the
returned root epoch. Epoch zero keeps the original `dstack-kms-issued` format.

Restart CVMs after advancing the policy. A running CVM continues to use its boot
key pair; omitted guest-agent GetKey selectors mean that CVM's boot epochs, not a
fresh chain lookup. Explicit historical requests select each dimension
independently and cache by the complete pair. Historical requests must be approved
in the selected root/app rows. Revoking one row does not revoke other rows or
keys already delivered. Supplied `trusted_ca` always pins the KMS connection,
regardless of epoch selection; historical responses cannot replace that pin.

The guest migrates disk headers and environment ciphertext if either dimension
changes and rejects future epochs in either dimension. LUKS tokens record both
epochs (missing app epoch means zero). Rekeying replaces the keyslot wrapping key;
it does not rotate the volume encryption key or erase host snapshots. Once a disk
header carries an epoch token, older guest images reject that header as malformed;
reverting the VM image therefore requires migrating the disk with a compatible
image or restoring a compatible header backup. App rotation isolates future app
keys from an exposed old derived key, but cannot recover from compromise of the
KMS root or revoke already disclosed secrets.

## SDK selection

Both selectors are optional; specify zero explicitly to recover an old key.
For example, Python `client.get_key("storage", "secp256k1", root_epoch=3,
app_epoch=0)` selects exactly that pair. JavaScript uses
`client.getKey("storage", "secp256k1", 3, 0)`. Rust provides
`get_key_at_epochs(..., Some(3), Some(0))`; Go provides `GetKeyAtEpochs` with
pointer selectors. Responses report both epochs. Existing root-only helpers
continue to use the CVM's current app epoch.

Sealing helpers also accept app epochs: `seal_env_at_epochs` (Rust),
`SealEnvAtEpochs` (Go), and the optional final argument of `sealEnv` / `seal_env`
(JavaScript / Python). See [SealedEnv](sealed-env.md) for the wire and signature
formats. The VMM UI and CLI use the epochs returned with the encryption key. SealedEnv
uses a single version-1 format that always includes both epochs.
