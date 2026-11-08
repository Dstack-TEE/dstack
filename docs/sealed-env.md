# Sealed environment variables

SealedEnv protects environment variables with HPKE and identifies the KMS root
and application key epochs needed to decrypt them. Plaintext remains inside the client and CVM;
the VMM stores and forwards ciphertext.

## Wire format

The `.sealed-env` file contains UTF-8 JSON:

```json
{"version":1,"root_epoch":3,"app_epoch":0,"enc":"<base64>","ciphertext":"<base64>"}
```

Version 1 fixes RFC 9180 Base mode with DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, and AES-256-GCM. `enc` is a 32-byte encapsulated key; `ciphertext`
includes the 16-byte authentication tag. Binary fields use standard padded
Base64. HPKE `info` is UTF-8 `dstack-sealed-env-v1:R:A`, where `R` and `A` are the canonical
decimal uint32 root and app epochs, with no leading zeros. AAD is empty. Unknown envelope
versions are rejected; extra JSON fields may be ignored. This provides
confidentiality, not authentication of the person uploading the environment.

Plaintext uses the existing JSON representation:

```json
{"env":[{"key":"MESSAGE","value":"Hello"}]}
```

The guest still enforces the application's environment-name allowlist.

## Keys and signatures

`GetSealedEnvPubKey` is available on KMS and proxied by VMM. Its request contains
`app_id` (20 bytes) only and always selects the current active epochs. Historical
private keys for decryption and migration are obtained through `GetAppKey`, not
through either environment public-key endpoint. The response contains
`public_key`, `root_epoch`, `app_epoch`, `timestamp`, and `signature`.

For each app, the KMS derives the 32-byte receiver private key directly from
that epoch's P-256 CA private scalar using HKDF-SHA256:

- salt: ASCII `dstack-sealed-env-v1`;
- IKM: the 32-byte P-256 private scalar;
- info: the raw 20-byte app ID.

`GetAppKey` returns it as `sealed_env_key` alongside the legacy key. The legacy
key derivation remains unchanged. This PR reserves app epochs and accepts only zero.

The public-key response signs Keccak256 of this unambiguous byte sequence:

```text
"dstack-sealed-env-pubkey-v1:" || app_id[20] || root_epoch[4, big-endian]
    || app_epoch[4, big-endian] || public_key[32] || timestamp[8, big-endian]
```

The signing key is the selected epoch's secp256k1 root. The signature is
`r[32] || s[32] || recovery_id[1]`. Clients must compare the recovered signer
against an independently trusted epoch root key or pin. Recovering a signer
alone is not a trust decision. Clients should reject stale responses (default
maximum age 300 seconds, future clock tolerance 60 seconds).

## Image compatibility

New image `metadata.json` files declare `"sealed_env": true`; `ListImages` exposes
this flag. Missing metadata means legacy encryption only. The UI and CLI use the target
image for both creation and environment updates, including image changes.
Old or unknown images use legacy encryption even with a capable KMS. Capable images require the SealedEnv RPC: CLI and UI fail on any lookup error,
including "service not found". Such errors are not signed and must not select a
weaker encryption protocol. Upgrade the KMS before submitting secrets for a
SealedEnv-capable image.

The VMM also enforces the flag for API callers and `dstack-vmm run`, including
existing SealedEnv files in a reused one-shot workdir. Creation, updates and image changes
through resize reject an effective SealedEnv file when the target image lacks the
capability, before writing files or changing resources. An update may replace it
with nonempty legacy `encrypted_env` while switching to an older image. Empty env
fields preserve the existing format. Guest `UpdateSealedEnv` uploads also require
a capable running image.

SealedEnv has one format, version 1, with both epoch fields always present.
This PR accepts app epoch zero only; the field is reserved for application key
rotation without changing this format. Signature and HPKE contexts always include
both epochs, including zero. Changing either epoch invalidates authentication.

The browser UI receives the key through the same-origin VMM API and does not
independently verify the response signer or freshness. Its trust boundary includes
the VMM and the configured KMS connection; it does not provide the independently
pinned signer verification described above. Use the CLI with a trusted signer
allowlist, or an SDK verification helper with an independently trusted signer,
when that verification is required.

## File precedence and migration

A new guest chooses `.sealed-env` whenever that file exists. An empty, invalid,
or unreadable sealed file is an error; it must not fall back to a legacy file.
If no sealed file exists, the guest accepts `.encrypted-env` for compatibility.
The copy limits are 384 KiB for sealed JSON and 256 KiB for legacy ciphertext.

At boot, sealed ciphertext explicitly selects its historical root/app epoch pair. The
guest obtains that epoch's app key over the already trusted KMS connection,
decrypts, and seals to the current epoch. Legacy ciphertext uses the legacy
key path at app epoch zero, trying earlier root epochs when necessary. It is
converted to SealedEnv only when decrypted with a historical epoch. Ciphertext
already decryptable with the current keys is left unchanged, even in the legacy
format; an older KMS need not provide a SealedEnv key in that case.
A future epoch or failed authentication stops environment provisioning.

The guest sends `UpdateSealedEnv` through the host channel before application
code runs. The VMM binds the update to the VM's CID and a snapshot of both env
files, including presence. It accepts at most one update in the boot window;
an empty update closes the window without replacing files. Owner updates and
guest replacement share the VM launch lock so an owner change cannot be lost
between the snapshot comparison and write.

VM creation and update accept either `sealed_env` or legacy `encrypted_env`.
Supplying both nonempty fields is rejected. Writing one format removes the other:
an external legacy update after a guest sealed update therefore becomes the
sole environment for the next boot. Omitting both preserves existing files on
update. A replacement is safely written before the other file is removed;
filesystem errors are reported rather than ignored.

Old OS images understand only `.encrypted-env`. After conversion removes that
file, reverting to an old OS requires the owner to upload legacy ciphertext
again. Rotation does not revoke credentials exposed before migration, and
cannot erase old host snapshots.

## Scope of verification

Local tests exercise HPKE implementations with synthetic keys, signature
contexts, file precedence and update races. They do not establish production
TEE isolation or real-chain availability. The shared fixture under
`sdk/fixtures/sealed-env/` is public test data, never deployment key material.
