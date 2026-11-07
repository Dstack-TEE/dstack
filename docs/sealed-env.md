# Sealed environment variables

SealedEnv protects environment variables with HPKE and identifies the KMS root
key epoch needed to decrypt them. Plaintext remains inside the client and CVM;
the VMM stores and forwards ciphertext.

## Wire format

The `.sealed-env` file contains UTF-8 JSON:

```json
{"version":1,"root_epoch":3,"enc":"<base64>","ciphertext":"<base64>"}
```

Version 1 fixes RFC 9180 Base mode with DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, and AES-256-GCM. `enc` is a 32-byte encapsulated key; `ciphertext`
includes the 16-byte authentication tag. Binary fields use standard padded
Base64. HPKE `info` is UTF-8 `dstack-sealed-env-v1:N`, where `N` is the canonical
decimal `root_epoch` uint32, with no leading zeros. AAD is empty. Unknown envelope
versions are rejected; extra JSON fields may be ignored. This provides
confidentiality, not authentication of the person uploading the environment.

Plaintext uses the existing JSON representation:

```json
{"env":[{"key":"MESSAGE","value":"Hello"}]}
```

The guest still enforces the application's environment-name allowlist.

## Keys and signatures

`GetSealedEnvPubKey` is available on KMS and proxied by VMM. Its request contains
`app_id` (20 bytes) and optional `root_epoch`; omission selects the current
active epoch, while future epochs are rejected. The response contains
`public_key`, `root_epoch`, `timestamp`, and `signature`.

For each app, the KMS derives the 32-byte receiver private key directly from
that epoch's P-256 CA private scalar using HKDF-SHA256:

- salt: ASCII `dstack-sealed-env-v1`;
- IKM: the 32-byte P-256 private scalar;
- info: the raw 20-byte app ID.

`GetAppKey` returns it as `sealed_env_key` alongside the legacy key. The legacy
key derivation and `GetAppEnvEncryptPubKey` remain unchanged.

The public-key response signs Keccak256 of this unambiguous byte sequence:

```text
"dstack-sealed-env-pubkey-v1:" || app_id[20] || epoch[4, big-endian]
    || public_key[32] || timestamp[8, big-endian]
```

The signing key is the selected epoch's secp256k1 root. The signature is
`r[32] || s[32] || recovery_id[1]`. Clients must compare the recovered signer
against an independently trusted epoch root key or pin. Recovering a signer
alone is not a trust decision. Clients should reject stale responses (default
maximum age 300 seconds, future clock tolerance 60 seconds).

## File precedence and migration

A new guest chooses `.sealed-env` whenever that file exists. An empty, invalid,
or unreadable sealed file is an error; it must not fall back to a legacy file.
If no sealed file exists, the guest accepts `.encrypted-env` for compatibility.
The copy limits are 384 KiB for sealed JSON and 256 KiB for legacy ciphertext.

At boot, sealed ciphertext explicitly selects its historical root epoch. The
guest obtains that epoch's app key over the already trusted KMS connection,
decrypts, and seals to the current epoch. Legacy ciphertext uses the legacy
key path, trying earlier epochs when necessary, and is converted to SealedEnv.
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
