# Application key epochs

Application owners can rotate their app's derived keys without rotating KMS root
keys or other apps. This extends SealedEnv (#1528); the PR dependency order is
#1519 → #1517 → #1520 → #1521 → #1528 → application epochs.

## Authorization and rotation

`checkAppAuthorization` returns `currentAppEpoch` together with the current root
epoch and its chain hash. `requestedRootEpoch` and `requestedAppEpoch` are
independent `OptionalEpoch` values: omitted selects current, explicit zero selects
historical epoch zero. Future epochs are denied through `rejectionReason`.
`checkKmsAuthorization` remains separate and uses app epoch zero.

`DstackApp.currentAppEpoch` starts at zero. Its owner calls
`advanceAppEpoch(expectedCurrentEpoch)` to increment it. The expected value
prevents a stale or retried transaction from advancing twice. Epochs cannot be
rolled back and are limited to uint32. `AdvanceAppEpoch` in `Manage.s.sol` exposes
this operation; `GetAppEpoch` in `Query.s.sol` reads it. Upgrade the app policy
implementation before advancing, and upgrade the KMS/auth backend and guests
before using nonzero epochs. Legacy policies without the ERC-165 `IAppEpoch`
capability remain at zero; failures of an advertised getter propagate.

The Ethereum auth backends query the policy through the KMS contract. The simple
backend reads `apps[appId].currentAppEpoch` (default zero); operators must preserve
its monotonicity. Public encryption-key lookup uses `GET /app/:appId` to read this
value. Legacy boot authorization and legacy environment public-key issuance are
rejected once the app epoch is nonzero, preventing old clients from silently
continuing with epoch-zero keys.

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
independently and cache by the complete pair. Historical access still requires
current app authorization. Supplied `trusted_ca` always pins the KMS connection,
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
