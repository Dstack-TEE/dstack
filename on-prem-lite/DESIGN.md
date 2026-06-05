<!-- SPDX-License-Identifier: Apache-2.0 -->
# on-prem-lite — KMS-less single-CVM licensed workload

A simpler profile of [`on-prem`](../on-prem): **drop the KMS CVM and key-broker
entirely**. The Courier CLI coordinates the vendor **Authority** directly with the
**workload CVM's launcher**. The workload disk is sealed by the CVM's **vTPM**
(`key_provider=tpm`), so no KMS is needed to derive keys. The launcher terminates the
courier itself, attests, and the Authority returns just **one image CEK + one signed
License** for the specific workload it asks for. The License has an expiry; when it lapses
the launcher stops the workload.

## When to use this vs `on-prem`

| | `on-prem` (KMS) | `on-prem-lite` (this) |
|---|---|---|
| Tiers | KMS CVM **+** workload CVM | workload CVM only |
| Workload keys | KMS-derived (`getKey`, portable across redeploy) | none — disk is vTPM-sealed, app gets only the image |
| Image keys delivered | whole vendor keyring (leased over mTLS) | **one CEK**, HPKE-sealed to this launcher |
| Runtime entitlement | lease auto-renewed from in-VPC KMS (no operator) | **License** with expiry; renewed by an operator courier run |
| Identity gate | `app_id` + `compose_hash` | `compose_hash` (launcher build) **+** `app_id` (which app) |
| Best for | apps needing a persistent cryptographic identity, many apps, gateway | "run a vendor's encrypted container + licensing", stateless |

Trade-offs (accepted for this profile): no portable/deterministic app keys (vTPM keys
are per-VM, lost on rebuild — fine, no migration); no in-VPC online anti-rollback anchor
(the launcher holds its own License high-water — operator disk-snapshot rollback is an
accepted residual risk, same TODO as `on-prem`); license renewal frequency is coupled to
operator courier runs (so use long licenses).

## Actors

```
 vendor host (internet)            operator host                 workload CVM (TDX+vTPM, air-gapped)
 ┌──────────────┐                  ┌──────────────┐              ┌───────────────────────────────┐
 │  Authority   │  ◀── courier ──▶ │ license-ctl  │  ◀── IAP ──▶ │ launcher (terminates courier, │
 │ +dstack-verif│   (untrusted     │  (CLI relay) │   tunnel     │  attests, decrypts, runs,     │
 └──────────────┘    blob relay)   └──────────────┘              │  enforces the License)        │
                                                                 └───────────────────────────────┘
```

- **Authority** — holds the Ed25519 License-signing key (`AUTHORITY_PUBKEY`, pinned into
  the measured launcher compose) and the per-image EC P-256 decryption keypairs (encrypt
  with the public key; the private key is the CEK, sealed per-launcher and never published).
  Verifies the launcher's TDX+vTPM quote via `dstack-verifier`.
- **license-ctl** (operator) — untrusted courier relay: moves opaque blobs between the
  Authority and the launcher's HTTP port over an IAP tunnel. Never a trust anchor.
- **launcher** (workload CVM) — terminates the courier, produces the attestation, verifies
  the License signature against the pinned `AUTHORITY_PUBKEY`, HPKE-opens the CEK, decrypts
  the workload image, runs it, and stops it when the License expires.

## Protocol

Same courier shape as `on-prem` Phase A/B, but **one hop** (Authority ↔ launcher) and the
payload is a per-workload `{CEK, License}` instead of a root + keyring.

```
 license-ctl(operator)     Authority         Verifier      launcher(workload CVM)   guest-agent
   │  challenge ───────────▶│                                                            
   │◀── nonce (HMAC,TTL) ───│                                                            
   │  courier/init ─────────────────────────────────────▶│ gen X25519 transport kp      
   │                                                      │ rd=SHA512(nonce‖tpub‖ts)     
   │                                                      │ Attest(rd) ────────────────▶│ TDX+vTPM
   │◀──── transport_pub, ts, attestation, vm_config ──────│◀───────────── quote+evlog ──│
   │  license(nonce,tpub,ts,attest,vm_config,workload) ──▶│                              
   │                                          verify ────▶│ G1 quote ✓                   
   │                                                       │ G2 report_data == rd        
   │                                                       │ G3 tcb ✓                    
   │                                                       │ G4 os_image ✓ (optional)    
   │                                                       │ G5 key_provider == tpm      
   │                                                       │ G6 compose_hash ∈ allowed   
   │                                                       │ G6b app_id ∈ tenant apps    
   │                                                       │ G7 workload ∈ app's allowed 
   │                              sealed_cek = HPKE(→tpub, image privkey)               
   │                              license = Ed25519-sign(seq++, expires_at, …)          
   │◀──────── { sealed_cek, license } ────────────────────│                              
   │  courier/install({sealed_cek, license}) ────────────▶│ verify sig (pinned PUBKEY)   
   │                                                       │ seq strictly ↑              
   │                                                       │ now ∈ [nbf, exp]            
   │                                                       │ compose_hash == self        
   │                                                       │ HPKE-open → CEK             
   │                                                       │ decrypt workload@digest     
   │                                                       │ compose up + start watchdog 
```

Renewal / workload update is the **same `courier/init` → `license` → `courier/install`**
run again: a higher `seq`, a later `expires_at`, optionally a new `workload.digest`
(rolling update). The launcher rejects a `seq ≤` its stored high-water (anti-rollback).

## The License

A License is a compact JSON object signed with the Authority's Ed25519 key. The launcher
verifies it against the `AUTHORITY_PUBKEY` **measured into its own compose** (so a tampered
Authority can't forge one, and a tampered launcher changes its `compose_hash` and is
refused at the Authority). Signature is Ed25519 over the **canonical JSON** (keys sorted,
compact `,`/`:` separators) of the object **minus** `authority_sig` — identical convention
to `on-prem`, so the Rust verifier and Python signer interop.

```json
{
  "schema_version": 1,
  "license_id": "acme-7",
  "tenant_id": "acme",
  "app_id": "078a2ffea340832bb5d3e9eb317aad6aed067d49",
  "compose_hash": "0x<launcher compose hash>",
  "workload": {
    "image": "us-central1-docker.pkg.dev/proj/repo/whoami-enc",
    "digest": "sha256:68a20f03…",
    "kid": "vendor-2026h1"
  },
  "seq": 7,
  "issued_at": 1730000000,
  "not_before": 1730000000,
  "expires_at": 1733000000,
  "grace_period_secs": 300,
  "authority_sig": "<base64 ed25519 over canonical(this minus authority_sig)>"
}
```

Delivered alongside the License (not inside it, since it's confidential):

```
sealed_cek = base64( HPKE-seal(transport_pub, <PEM of the image private key for `kid`>) )
            // RFC 9180 DHKEM-X25519 / HKDF-SHA256 / AES-256-GCM, info="dstack-lite-cek-v1"
```

**Field semantics**

- `compose_hash` — the launcher's measured compose = **which launcher build** (the same
  across all apps/customers running this launcher release). The Authority checked the
  *attested* value ∈ `allowed_launcher_digests`; the launcher additionally checks
  `license.compose_hash == its own`. This says "trusted launcher build", not "which app".
- `app_id` — **which app** (the boot-config value measured into MRCONFIGID, returned by the
  verifier as `app_info.app_id`). The Authority assigns it (`create-app`), scopes each app's
  `allowed_workload_digests` under it, and gates the *attested* `app_id` ∈ the tenant's
  registered apps; the launcher checks `license.app_id == its own`. This is what
  distinguishes one workload from another and gives per-app isolation **within** a tenant
  (two apps on the same launcher build share a `compose_hash` but differ by `app_id`).
- `workload.{image,digest,kid}` — which encrypted image this License authorizes and which
  image key the `sealed_cek` carries; the digest is gated against **this app's**
  `allowed_workload_digests`. The launcher pulls strictly `image@digest`.
- `seq` — monotonic per `(tenant_id, compose_hash)`. The launcher persists the highest seq
  it has installed and refuses `seq ≤ stored` → **anti-rollback / anti-downgrade** (G8-equiv).
- `expires_at` + `grace_period_secs` — hard stop. A watchdog stops the workload once
  `now > expires_at + grace_period_secs`. `not_before` guards clock-skew/pre-dating.
- The Authority sets `expires_at = issued_at + LICENSE_TTL`, where `LICENSE_TTL` is
  configurable (global env `LICENSE_TTL_SECS`, optional per-tenant override). **Trial:** set
  a very large TTL (e.g. 3650d) so no renewal is needed during evaluation.

**What the License does and doesn't guarantee**

- ✅ Only an attested launcher running a vendor-approved `compose_hash` on a vTPM-sealed
  disk, asking for an allowed `workload.digest`, gets a CEK — and only its own CEK, sealed
  to its own transport key (a clone/other launcher can't open it).
- ✅ Expiry is enforced launcher-side; a still-valid License can't be forged or extended
  (signed). Stopping the courier just lets the current License run out.
- ⚠️ Wall-clock is assumed trustworthy inside the CVM (same trusted-time assumption
  `on-prem` makes for the KMS). A host that freezes the guest clock could defer expiry.
- ⚠️ A disk-snapshot rollback could revert the launcher's stored `seq` high-water and
  replay a superseded License within its original validity window — accepted residual risk
  (no online anchor in this profile; mirrors `on-prem`'s rollback TODO).

## Fail-closed gates (the whole policy surface)

| # | Gate | Enforced at | Rejects when… |
|---|---|---|---|
| G1 | quote authentic | Authority/Verifier | TDX+vTPM quote not hardware-rooted |
| G2 | `report_data` binding | Authority | quote not bound to this session's `transport_pub`/nonce |
| G3 | tcb status | Authority | tcb ∉ allowed (empty/missing ⇒ deny) |
| G4 | os-image hash | Authority | os-image ∉ whitelist (when configured; optional in this profile) |
| G5 | `key_provider == tpm` | Authority | disk not vTPM-sealed |
| G6 | launcher `compose_hash` | Authority **+** launcher | compose ∉ `allowed_launcher_digests`; or License ≠ self |
| G6b | `app_id` | Authority **+** launcher | attested app_id ∉ the tenant's registered apps; or License ≠ self |
| G7 | workload digest | Authority | digest ∉ **the app's** `allowed_workload_digests` |
| G8 | License signature | launcher | sig ≠ pinned `AUTHORITY_PUBKEY` |
| G9 | License `seq` monotonic | launcher | `seq ≤ stored` (rollback) |
| G10 | License validity window | launcher | `now ∉ [not_before, expires_at(+grace)]` ⇒ stop workload |

Every list-based gate denies on the empty list. `compose_hash` gates the launcher build;
`app_id` gates which app (and scopes G7's digest whitelist).

## Components

| Path | What |
|---|---|
| `authority/` | vendor Authority (FastAPI): `/challenge`, `/license`, admin (tenants, apps + per-app `allowed_workload_digests`, image keys, policy); reuses the `on-prem` HPKE + Ed25519 + verifier conventions |
| `cli/license-ctl.py` | operator courier CLI: `attest` (issue+install a License), `renew`, `status` |
| `launcher/` | the lite launcher (Rust): courier HTTP server, attest, License verify + CEK unseal, decrypt+run, expiry watchdog |
| `deploy-templates/workload/` | single-CVM compose + `app.json` (`key_provider=tpm`), `AUTHORITY_PUBKEY` + workload pins literal |
