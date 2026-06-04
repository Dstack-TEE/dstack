<!-- SPDX-License-Identifier: Apache-2.0 -->
# Protocol at a glance (GCP private deployment)

The cryptographic protocol behind the deployment — **what message carries what, and
what is verified at each hop**. For commands see [`QUICKSTART.md`](QUICKSTART.md); for
the operational walkthrough see [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md).

> 中文: [`PROTOCOL_CN.md`](PROTOCOL_CN.md)

## Actors & trust roots

| Actor | Where | Holds / proves |
|---|---|---|
| **Authority** | vendor host (online) | Ed25519 **AuthBundle signing key** (its pubkey = `AUTHORITY_PUBKEY`, the **root of authz trust**, pinned into the measured KMS compose); per-tenant **KMS root** (P-256 root-CA + secp256k1 k256); **global image keyring** (EC P-256 private keys) |
| **Verifier** | vendor host | validates the TDX+vTPM quote, replays the event log, extracts `os_image_hash` / `compose_hash` / `key_provider` / `tcb_status` / `report_data` |
| **Courier CLI** (`kms_ctl.py` / `dstack-cloud`) | operator host | **untrusted relay** — moves opaque blobs between Authority and the CVM. Never a trust anchor |
| **key-broker** | inside KMS CVM (TEE) | terminates the courier; HPKE-opens the sealed root; verifies the AuthBundle; materializes the KMS keyset; serves `bootAuth` + `lease` to workloads |
| **dstack-kms** | inside KMS CVM (TEE) | boots from the materialized keyset, serves TLS `:8000`, derives per-app keys |
| **launcher** | inside workload CVM (TEE) | RA-TLS client to the key-broker; leases the image keyring; decrypts the JWE image; runs + supervises the workload |
| **guest-agent** | inside each CVM | produces the TDX+vTPM attestation and binds it to `report_data` |

**Trust spine:** the vendor controls one secret (the Ed25519 signing key). Its public
half is *measured into* the KMS compose, so a tampered Authority cannot forge an
AuthBundle, and a tampered compose changes `compose_hash` and is rejected at provision.

---

## Phase A — KMS provisioning (courier attest)

Goal: hand the KMS its root key **without the operator ever seeing it**, and only to a
CVM the vendor has cryptographically approved.

```
guest-agent  key-broker      CLI(operator)    Authority       Verifier
 │                │                │──challenge──▶│               │
 │                │                │◀───nonce─────│               │
 │                │◀─courier/init──│              │               │
 │                │ gen X25519 kp  │              │               │
 │                │ rd=SHA-512(…)  │              │               │
 │◀──Attest(rd)───│                │              │               │
 │─TDX+vTPM quote▶│                │              │               │
 │                │─tpub,ts,attest▶│              │               │
 │                │                │──provision──▶│               │
 │                │                │              │────verify────▶│
 │                │                │              │◀───verdict────│
 │                │                │              │ G1 quote✓     │
 │                │                │              │ G2 rd-bind✓   │
 │                │                │              │ G3 tcb✓       │
 │                │                │              │ G4 os_image✓  │
 │                │                │              │ G5 kp=tpm✓    │
 │                │                │              │ G6 compose✓   │
 │                │                │              │ HPKE-seal root│
 │                │                │              │ Ed25519-sign  │
 │                │                │              │ seq++         │
 │                │                │◀root+bundle──│               │
 │                │◀───install─────│              │               │
 │                │ verify sig     │              │               │
 │                │ seq strictly↑  │              │               │
 │                │ HPKE-open root │              │               │
 │                │ SAN = CVM IP   │              │               │
 │                │ keyset → _ready│              │               │
 │                │ kms → :8000    │              │               │
```

1. **challenge** — CLI authenticates with its tenant API key; Authority returns a
   stateless HMAC `nonce` (TTL-bounded).
2. **courier/init** — the key-broker mints a **per-session X25519 transport keypair**,
   stamps `kms_ts`, computes
   `report_data = SHA-512(nonce ‖ transport_pub ‖ kms_ts_LE)` (64 B), and asks the
   guest-agent for a full **TDX + vTPM** attestation over that `report_data`. Returns
   `transport_pub`, `kms_ts`, the attestation, and `vm_config`.
3. **provision** — Authority replays the nonce (MAC + TTL), checks clock skew ≤ 300 s,
   sends the attestation to the Verifier, and runs the six fail-closed gates (G1–G6
   below) on the returned verdict.
   On success it **HPKE-seals** the root payload (P-256 root-CA key + k256 scalar +
   domain) **to `transport_pub`** → `sealed_root`, bumps `bundle_seq`, and **Ed25519-signs**
   the AuthBundle (app whitelist + global image keyring + os-image whitelist + revocations).
4. **courier/install** — the key-broker **verifies the AuthBundle signature** against the
   compose-pinned `AUTHORITY_PUBKEY`, enforces **`bundle_seq` strictly increasing**
   (anti-rollback), **HPKE-opens** `sealed_root` with the session transport secret (only
   this TEE holds it), sets the **rpc-cert SAN to the CVM's own internal IP**, materializes
   the dstack-kms keyset (`root-ca` / `tmp-ca` / `rpc` / `k256`), and writes `_ready`.
5. **boot** — dstack-kms's wait-loop sees `_ready`, exec's, and serves TLS on `:8000`.
   At its own boot it calls the key-broker `bootAuth/kms`, which **re-checks** os-image +
   tcb + device fail-closed.

The operator's CLI only ever holds two **opaque** blobs (`sealed_root`, `auth_bundle`).
G2 is the anti-substitution lynchpin: a genuine quote that isn't bound to *our*
`transport_pub` is rejected, so the relaying CLI cannot swap in a key it controls.

---

## Phase B — Workload launch (RA-TLS lease)

Goal: a workload CVM gets the image-decryption keys **only after re-proving** its
identity to the (now-running) KMS, and loses them if it stops re-proving.

```
 launcher(workload CVM)        key-broker(KMS CVM)
   │  bootAuth/app(BootInfo) ─────▶│  os_image✓ tcb✓ app_id✓ compose✓ device✓ (fail-closed)
   │◀──────────── allowed ─────────│
   │  RA-TLS handshake ───────────▶│  mutual; launcher cert embeds its TDX quote
   │  get version ────────────────▶│
   │◀── image_digest, bundle_seq ──│
   │  lease/acquire(instance,compose,digest) ─▶│  re-run gates + digest ∈ allowed_workload_digests
   │                                            │  bind slot_id → (instance, compose)
   │◀──────── Lease(signed) + keyset ───────────│
   │  write privkeys → tmpfs                    
   │  skopeo/ocicrypt JWE decrypt(image@digest) 
   │  run decrypted workload                    
   │  ── every ttl/3 ── lease/renew(slot,instance) ─▶│
   │       on fail → re-acquire (re-runs every gate) │
   │       still fail past grace → stop containers   │   ← fail-closed at runtime
```

1. **bootAuth/app** — before anything decrypts, the key-broker gates the boot on the
   measured `BootInfo` (os-image, tcb, app_id, compose_hash, device).
2. **RA-TLS** — mutual TLS where the launcher's client cert **embeds its TDX quote**, so
   the key-broker authenticates the *hardware*, not a bearer token.
3. **lease/acquire** — re-runs the auth gates, additionally requires
   `image_digest ∈ app.allowed_workload_digests`, **binds a `slot_id`** to
   `(instance_id, compose_hash)` (anti-clone), and returns a **signed Lease + the keyset**
   (the global image private keys).
4. **decrypt + run** — the launcher hands every leased private key to `skopeo`; ocicrypt
   (native JWE, ECDH-ES) decrypts with whichever key is the image's recipient, then runs it.
5. **renew** — every `ttl/3` the launcher renews; a renewal failure triggers a full
   re-acquire (re-running **all** gates against the live AuthBundle); if that still fails
   past the grace window the workload containers are **stopped** — entitlement is
   continuous, not one-shot.

---

## Fail-closed gates (the whole policy surface)

| # | Gate | Enforced at | Rejects when… |
|---|---|---|---|
| G1 | quote authentic | Authority/Verifier | the TDX+vTPM quote isn't hardware-rooted |
| G2 | `report_data` binding | Authority | quote not bound to this session's `transport_pub`/nonce |
| G3 | tcb status | Authority **+** key-broker | tcb ∉ allowed (empty/missing ⇒ deny) |
| G4 | os-image hash | Authority **+** key-broker | os-image ∉ whitelist (**empty ⇒ deny**) |
| G5 | key_provider == `tpm` | Authority | disk not vTPM-sealed (`kms`/`local`/`none`) |
| G6 | KMS compose hash | Authority | compose ∉ kms-compose whitelist (**empty ⇒ deny**) |
| G7 | AuthBundle signature | key-broker | sig ≠ pinned `AUTHORITY_PUBKEY` |
| G8 | `bundle_seq` monotonic | key-broker | `new_seq ≤ stored_seq` (rollback) |
| G9 | app_id ∈ whitelist | key-broker | app not registered for this tenant |
| G10 | launcher compose hash | key-broker | compose ∉ `allowed_launcher_digests` / revoked |
| G11 | workload image digest | key-broker | digest ∉ `allowed_workload_digests` |
| G12 | lease alive | launcher | renew + re-acquire fail past grace ⇒ stop workload |

Every list-based gate denies on the **empty** list — an unconfigured policy is a *closed*
policy, never an open one.

## Cryptographic primitives

- **Quote binding** — `report_data = SHA-512(nonce ‖ transport_pub ‖ kms_ts_LE)`; the
  same formula is recomputed by the Authority (G2). Ties one specific quote to one
  specific session transport key.
- **Root sealing** — HPKE (RFC 9180): `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` +
  `AES-256-GCM`, base mode, `info = "dstack-courier-root-v1"`. Sealed to the per-session
  `transport_pub`; openable only inside the TEE that minted it.
- **AuthBundle** — Ed25519 over canonical (`sort_keys`, compact) JSON; verified against
  the `AUTHORITY_PUBKEY` **measured into** the KMS compose; `bundle_seq` strictly
  monotonic for anti-rollback.
- **Image encryption** — ocicrypt **native JWE** (ECDH-ES, EC P-256). Encrypt with the
  **public key only** (`skopeo copy --encryption-key jwe:pub.pem`); the build host never
  holds a decryption secret. Private keys are leased to attested launchers, which
  `--decryption-key` them; ocicrypt try-each-matches the recipient.
- **KMS root** — P-256 root-CA (the KMS KDF extracts its scalar to derive every app/disk/env
  key) + secp256k1 k256 (identity signatures). Authority-held for DR; HPKE-sealed per provision.

## Trust boundaries (read this twice)

- **HPKE protects the KMS root end-to-end** — `sealed_root` is confidential to the
  destination TEE, so the relaying operator never sees the KMS root or any derived key.
- **The AuthBundle is integrity-protected, not encrypted.** It is signed (G7) so the
  operator cannot *forge* or *alter* it, but its `keyring` (the global image private keys)
  travels **in cleartext** through the courier relay. So the operator who provisions the
  KMS is **inside the image-confidentiality boundary** — image encryption defends against
  the registry, the network, and image-at-rest, **not** against that operator. This is
  consistent with the design's stated v2 tradeoff ("the platform/vendor can decrypt
  customer data"); if your threat model needs to exclude the operator from image keys too,
  the bundle's `keyring` must additionally be HPKE-sealed to `transport_pub`.
