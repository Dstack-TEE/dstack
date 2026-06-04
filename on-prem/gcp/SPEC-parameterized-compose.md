<!-- SPDX-License-Identifier: Apache-2.0 -->
# Spec — customer-independent `compose_hash` via parameterized deploy composes

**For: codex.** Implement the design below. This is an authorization-correctness
change: get it wrong and either every customer needs a fresh compose audit, or an
attacker can swap the workload. Read the **Invariants** and **Security** sections
carefully; they are non-negotiable.

## 1. Goal

Make the **KMS-CVM** and **workload-CVM** `docker-compose.yaml` files produce a
**customer-independent `compose_hash`**, so the vendor pre-computes each hash
**once** and registers it in the authority (`allowed_kms_compose_hashes` for the
KMS CVM, `allowed_launcher_digests` for the workload CVM) for **all** customers —
no per-customer compose to re-audit.

## 2. Background (how it works today)

- dstack normalizes `docker_compose_file` → `deploy/<app>/shared/app-compose.json`
  and `compose_hash = sha256(app-compose.json)`. The authority gates on it.
- The compose currently hardcodes **customer-specific** values, so `compose_hash`
  differs per customer and the vendor cannot pre-pin it:
  - **image registry path**: `<region>-docker.pkg.dev/<project>/<repo>/...`
  - **SWP egress proxy IP**: `HTTP_PROXY=http://10.128.0.53:80` (KMS compose)
  - **KMS internal IP**: `KMS_URL` / `KEY_BROKER_URL=https://10.128.15.220:...` (workload compose)
- Security-critical values that are NOT customer-specific and MUST stay measured:
  - **image digests** (`@sha256:...`) — the content pin
  - **`AUTHORITY_PUBKEY`** — the AuthBundle trust anchor (per-vendor constant)

## 3. Design

In the compose, write customer-specific values as **literal `${VAR}`** and resolve
them at **runtime** via docker compose's native `${VAR}` expansion (fed by an
`.env` that `prelaunch.sh` writes). Keep security pins **literal**.

```yaml
# KMS compose (excerpt)
services:
  key-broker:
    image: ${DSTACK_REGISTRY}/key-broker@sha256:<PINNED_KEY_BROKER_DIGEST>
    environment:
      - AUTHORITY_PUBKEY=<PINNED_LITERAL_BASE64>          # literal, measured
      - HTTP_PROXY=http://${SWP_PROXY}                     # ${VAR}, runtime
  dstack-kms:
    image: ${DSTACK_REGISTRY}/dstack-kms@sha256:<PINNED_KMS_DIGEST>
```
```yaml
# workload compose (excerpt)
services:
  launcher:
    image: ${DSTACK_REGISTRY}/launcher@sha256:<PINNED_LAUNCHER_DIGEST>
    environment:
      - KMS_URL=https://${KMS_HOST}:8000
      - KEY_BROKER_URL=https://${KMS_HOST}:8002
      - WORKLOAD_IMAGE=${DSTACK_REGISTRY}/<workload-name>   # path only; digest comes
                                                            # from current_image_digest
```

Because `app-compose.json` contains the **literal** `${DSTACK_REGISTRY}` /
`${SWP_PROXY}` / `${KMS_HOST}` strings (not the expanded values) plus the literal
pinned digests and `AUTHORITY_PUBKEY`, `compose_hash` is identical across
customers.

## 4. Invariants (do not violate)

1. **Measured == reasoned.** The compose keeps literal `${VAR}`. **`prelaunch.sh`
   MUST NOT rewrite/`sed` the compose file** — it only writes the `.env` that
   docker compose reads. (If prelaunch edited the compose, the running compose
   would diverge from the measured one.)
2. **Content pin.** Every image ref is `${REGISTRY_VAR}/<name>@sha256:<PINNED>` —
   the digest is a **literal suffix in the compose, never from a variable**. A
   redirected registry then cannot substitute content (content-addressed); a
   malformed registry value yields two `@` → invalid ref → docker fails closed.
3. **No injection.** docker compose `${VAR}` expansion does **no escaping**.
   `prelaunch.sh` MUST validate every injected value against a strict allowlist
   regex before writing it; on any mismatch, **fail closed** (`exit 1` so the CVM
   does not boot the app). Injected values are **paths/IPs only — never digests,
   tags, or anything with shell/ref metacharacters**.

## 5. Parameterize vs pin

| value | in compose as | source | validation regex (anchored) |
|------|----------------|--------|------------------------------|
| registry prefix | `${DSTACK_REGISTRY}` | derive from metadata (region/project/ar-repo) — prelaunch already builds `${REGION}-docker.pkg.dev/$PROJECT/$AR_REPO`; OR user_config | `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?(/[a-z0-9._-]+)+$` |
| SWP egress IP:port | `${SWP_PROXY}` (`HTTP_PROXY=http://${SWP_PROXY}`) | user_config / metadata attr | `^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$` |
| KMS internal IP | `${KMS_HOST}` (`https://${KMS_HOST}:8000`) | user_config / metadata attr | `^([0-9]{1,3}\.){3}[0-9]{1,3}$` |
| image digests | literal `@sha256:<hex>` | **vendor (pinned)** | — (never a var) |
| `AUTHORITY_PUBKEY` | literal base64 | **vendor (constant)** | — (never a var) |

> The registry prefix is already derivable from the GCP metadata server (the
> prelaunch builds it today), which is the most robust source. Per the original
> design you may instead read it (and the IPs) from dstack's **user_config**;
> either is fine **as long as the value is validated and the digest stays pinned**.

## 6. Implementation tasks

1. **Verify the measurement assumption FIRST (blocking).** Confirm dstack computes
   `compose_hash` over `docker_compose_file` **with `${VAR}` literal (unexpanded)**.
   Check the guest-agent / dstack-cloud app-compose normalization. If dstack
   expands env vars before hashing, this whole approach is void — stop and report.
2. **Commit deploy templates** (the live `deploy/` dir is gitignored, so add
   reusable templates): `on-prem/gcp/deploy-templates/{kms,workload}/` containing
   `app.json`, `docker-compose.yaml` (parameterized as in §3, with
   `@sha256:<...DIGEST>` and `AUTHORITY_PUBKEY=<...>` placeholders), `prelaunch.sh`,
   and a short `README.md` explaining what the vendor fills once (digests,
   AUTHORITY_PUBKEY) vs what is resolved per-customer at runtime.
3. **`prelaunch.sh`** (extend the existing one):
   - Resolve `DSTACK_REGISTRY` (metadata region/project/ar-repo) and read
     `SWP_PROXY` / `KMS_HOST` from user_config (or instance metadata attributes).
   - **Validate** each against its §5 regex; on mismatch `echo "prelaunch: invalid
     <VAR>"; exit 1`.
   - **Write** them to the app's `.env` (the `env_file` docker compose reads).
     Confirm this `.env` is the one docker compose uses for `${VAR}` expansion at
     `up` time, and that prelaunch runs before app `compose up`.
4. **`allowed_envs`** — ensure the parameterization vars are permitted to reach the
   compose if dstack constrains env via `allowed_envs`. (These are non-secret
   path/IP vars, not the encrypted env.)
5. **Docs**: update `部署向导.md` §3/§4 and `DEPLOYMENT.md` to show the
   parameterized compose + that `compose_hash` is now customer-independent and
   pre-registered by the vendor.

## 7. Security requirements (restate)

- Digest `@sha256:<...>` and `AUTHORITY_PUBKEY` are **literal** in the measured
  compose. Never sourced from a variable.
- Injected values are validated (anchored regex, fail-closed). No `@`, no
  whitespace, no shell/ref metacharacters.
- `prelaunch.sh` does not modify the compose file; only writes `.env`.
- A redirected registry is harmless (content-addressed pull); a malformed one
  fails closed.

## 8. Acceptance criteria

- Two inputs with **different** project/registry/IPs, rendered through the same
  template, produce **byte-identical `app-compose.json`** → **identical
  `compose_hash`** (add a unit test that hashes the template for two synthetic
  metadata/user_config sets and asserts equality).
- A `DSTACK_REGISTRY` containing `@` / whitespace / uppercase → prelaunch rejects
  → app does not start (fail-closed test).
- On a real deploy, containers pull `<customer-AR>/<img>@sha256:<pinned>` and run;
  the pinned digests + `AUTHORITY_PUBKEY` are identical across customers.

## 9. Open questions for codex to resolve

- Does dstack hash the compose before or after `${VAR}` expansion? (Task 1 —
  blocking.)
- On-CVM path + format of dstack's user_config / `.user-config`; can `prelaunch.sh`
  read it before app `compose up`?
- Which `.env` does the app's `docker compose up` read for `${VAR}` expansion, and
  is it writable by prelaunch at that point?
- Does `allowed_envs` gate the parameterization vars?
