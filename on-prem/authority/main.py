# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Vendor authority: minimal authorization service for air-gapped KMS provisioning."""

import base64
import json
import logging
import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException

from crypto import (
    get_authority_pubkey_bytes,
    make_auth_bundle,
    make_root_payload,
    seal_root,
    issue_challenge,
    verify_challenge,
)
from models import (
    ChallengeRequest,
    ChallengeResponse,
    CreateUserRequest,
    CreateUserResponse,
    HashRequest,
    ListUsersResponse,
    MeasureRequest,
    MintKeyRequest,
    MintKeyResponse,
    ProvisionRequest,
    ProvisionResponse,
    RegisterImageRequest,
    SyncAuthRequest,
    SyncAuthResponse,
    UserInfo,
)
from store import Store
from verifier_client import VerifierError, compute_report_data, verify_attestation

logger = logging.getLogger(__name__)

app = FastAPI(title="dstack vendor authority", version="0.1.0")
store = Store()

# ─── multi-user auth ──────────────────────────────────────────────────────────
# When AUTHORITY_ADMIN_TOKEN is set the authority runs in multi-user mode:
#   • admin endpoints (gated by the admin token) create users, each with its own
#     independently-generated root key;
#   • operator endpoints (provision / sync-auth / challenge) require a per-user
#     API key, and a user can only ever act on its own root (strict isolation).
# When it is unset the authority stays in the legacy open/dev mode used by the
# localhost demo: no auth, customers auto-created on first use.
ADMIN_TOKEN = os.getenv("AUTHORITY_ADMIN_TOKEN", "")
AUTH_ENABLED = bool(ADMIN_TOKEN)

# Attestation verification via the repo's dstack-verifier service.
#   VERIFIER_URL          where dstack-verifier listens (docker-compose service)
#   REQUIRE_ATTESTATION   if true, a provision with no quote is rejected; if
#                         false (dev/non-TDX), a missing quote is allowed with a
#                         warning. A *present* quote is ALWAYS verified.
#   ALLOWED_TCB_STATUSES  comma list of acceptable tcb_status values
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://verifier:8080")
REQUIRE_ATTESTATION = os.getenv("REQUIRE_ATTESTATION", "false").lower() in ("1", "true", "yes")
# os_image_hash can only be verified when the CVM was deployed with a pinned
# os_image_hash. When it isn't, quote authenticity + RTMR/event-log + mr_aggregated
# (TOFU) still secure the flow, so this is optional by default.
REQUIRE_OS_IMAGE_HASH = os.getenv("REQUIRE_OS_IMAGE_HASH", "false").lower() in ("1", "true", "yes")
# Vendor-approved KMS OS image hash (UKI Authenticode hash, hex). On GCP the
# verifier extracts the ACTUAL UKI hash from the event log (PCR2 Event 28) and
# compares it to vm_config.os_image_hash — which is empty unless the deployment
# pinned it. The vendor knows its KMS image's hash, so we inject it here as the
# expected value; the verifier then truly verifies the measurement.
EXPECTED_OS_IMAGE_HASH = os.getenv("EXPECTED_OS_IMAGE_HASH", "").strip()
ALLOWED_TCB_STATUSES = {
    s.strip() for s in os.getenv("ALLOWED_TCB_STATUSES", "UpToDate,SWHardeningNeeded").split(",") if s.strip()
}

if AUTH_ENABLED:
    logger.info("multi-user mode: per-user API keys enforced")
else:
    logger.warning("open/dev mode: no auth (set AUTHORITY_ADMIN_TOKEN to enable multi-user)")


def _bearer(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


def require_admin(authorization: Optional[str] = Header(None)) -> None:
    """Gate admin endpoints behind the authority admin token. In open/dev mode
    (no AUTHORITY_ADMIN_TOKEN) everything is unauthenticated, so admin is open too."""
    if not AUTH_ENABLED:
        return
    import hmac
    if not hmac.compare_digest(_bearer(authorization), ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="invalid admin token")


def resolve_user(req_user_id: str, authorization: Optional[str]) -> str:
    """Determine which customer/root a request acts on.

    In multi-user mode the customer is derived from the caller's API key (the
    request's user_id, if given, must match) so a user cannot touch another
    user's root. In open mode the request's user_id is trusted and the
    customer is auto-created.
    """
    if not AUTH_ENABLED:
        return req_user_id
    cid = store.find_user_by_api_key(_bearer(authorization))
    if cid is None:
        raise HTTPException(status_code=401, detail="invalid or missing api key")
    if req_user_id and req_user_id != cid:
        raise HTTPException(
            status_code=403,
            detail=f"user_id '{req_user_id}' does not match authenticated user '{cid}'",
        )
    return cid


@app.get("/api/v1/authority-pubkey")
def authority_pubkey():
    """Return the authority Ed25519 public key.

    The CLI writes this into the key-broker during initial setup so the KMS
    can later verify AuthBundle signatures without contacting the authority.
    """
    return {"pubkey": base64.b64encode(get_authority_pubkey_bytes()).decode()}


def verify_kms_attestation(req: ProvisionRequest, user_id: str, user: dict) -> None:
    """Verify the KMS's TDX attestation via dstack-verifier before sealing the
    root to its transport key. Raises HTTPException on any policy failure.

    Critical check: the quote's report_data must equal
    SHA-512(nonce || transport_pub || kms_ts). Without it, HPKE-sealing to
    transport_pub is meaningless — an untrusted CLI could submit its own key.
    """
    attestation = (req.attestation or "").strip()
    if not attestation:
        if REQUIRE_ATTESTATION:
            raise HTTPException(status_code=400, detail="attestation required but none provided")
        logger.warning("provision %s: no attestation — SKIPPED (dev). "
                       "set REQUIRE_ATTESTATION=true in production", user_id)
        return

    # Approved measurements come from the runtime-managed policy (admin API).
    # Inject the os_image_hash into vm_config so the verifier can pin it — only
    # when exactly one is approved; with several, the membership check below (on
    # the measured value) is the gate.
    allowed_os = store.get_os_images()
    vm_config = req.vm_config
    if len(allowed_os) == 1:
        try:
            cfg = json.loads(vm_config) if vm_config else {}
        except (ValueError, TypeError):
            cfg = {}
        cfg["os_image_hash"] = allowed_os[0]
        vm_config = json.dumps(cfg)

    try:
        result = verify_attestation(VERIFIER_URL, attestation, vm_config)
    except VerifierError as e:
        raise HTTPException(status_code=502, detail=str(e))

    details = result.get("details", {})
    app_info0 = details.get("app_info") or {}
    logger.info(
        "verifier[%s]: is_valid=%s quote=%s eventlog=%s os_image=%s tcb=%s "
        "compose=%s kp_info=%s reason=%s",
        user_id, result.get("is_valid"), details.get("quote_verified"),
        details.get("event_log_verified"), details.get("os_image_hash_verified"),
        details.get("tcb_status"), app_info0.get("compose_hash"),
        app_info0.get("key_provider_info"), result.get("reason"),
    )

    # 1. the TDX(+vTPM) quote itself must be authentic (hardware-rooted).
    if not details.get("quote_verified"):
        raise HTTPException(status_code=403, detail=f"quote verification failed: {result.get('reason')}")

    # 2. report_data must bind this courier session's transport key (the core
    #    anti-substitution check — a genuine quote not bound to OUR transport
    #    key is rejected, so a relaying CLI cannot swap in its own key).
    expected = compute_report_data(req.nonce, req.transport_pub, req.kms_ts).hex()
    got = (details.get("report_data") or "").lower()
    if got != expected.lower():
        raise HTTPException(status_code=403,
                            detail="report_data mismatch: quote not bound to this transport key/nonce")

    # 3. TCB status must be acceptable
    tcb = details.get("tcb_status")
    if tcb not in ALLOWED_TCB_STATUSES:
        raise HTTPException(status_code=403, detail=f"unacceptable tcb_status: {tcb}")

    # 4. os_image_hash / measurement: the verifier only verifies these (and
    #    populates app_info.mr_aggregated) when the CVM was deployed with a
    #    pinned os_image_hash. When it wasn't (os_image_hash_verified=false),
    #    measurement-pinning isn't available — accept on quote+binding unless
    #    REQUIRE_OS_IMAGE_HASH demands it.
    if not details.get("os_image_hash_verified"):
        if REQUIRE_OS_IMAGE_HASH or allowed_os:
            raise HTTPException(status_code=403,
                                detail=f"os_image_hash not verified: {result.get('reason')}")
        logger.warning("provision %s: os_image_hash/measurement NOT verified and no approved "
                       "os_image configured; accepting on quote authenticity + report_data "
                       "binding only. Add one via POST /api/v1/admin/os-images in production.", user_id)

    # 5. KMS identity whitelist — pin on STABLE, semantic measurements instead of
    #    mr_aggregated. On GCP, mr_aggregated = sha256(PCR0 ‖ PCR2 ‖ runtime_pcr)
    #    and PCR0 (the vTPM firmware/launch measurement) changes every instance,
    #    so pinning it forced a re-pin on every redeploy. Instead we require:
    #      a) os_image_hash == the vendor-approved OS image (EXPECTED_OS_IMAGE_HASH)
    #      b) key_provider == "tpm"   (GCP vTPM-sealed disk; reject kms/local/none)
    #      c) compose_hash ∈ the user's whitelist (explicit list if configured,
    #         else trust-on-first-use). compose_hash is stable across redeploys
    #         and only changes on an intentional compose change (→ re-review).
    app_info = details.get("app_info") or {}
    os_hash = (app_info.get("os_image_hash") or "").lower()
    compose_hash = (app_info.get("compose_hash") or "").lower()

    # a) os_image_hash — FAIL-CLOSED: must be in the runtime-managed whitelist
    #    (manage via POST/DELETE /api/v1/admin/os-images; discover a new image's
    #    hash with the read-only `kms_ctl.py measure`).
    if not allowed_os:
        raise HTTPException(status_code=403,
                            detail="no approved os_image_hash (fail-closed; add one via "
                                   "POST /api/v1/admin/os-images — discover with `kms_ctl.py measure`)")
    if os_hash not in allowed_os:
        raise HTTPException(status_code=403,
                            detail=f"os_image_hash not in whitelist: {os_hash or 'none'}")

    # b) key_provider must be tpm. key_provider_info is the hex of the JSON
    #    {"name": "<none|local-sgx|tpm|kms>", "id": "<pubkey>"} measured at boot.
    kp_name = ""
    kp_hex = app_info.get("key_provider_info") or ""
    if kp_hex:
        try:
            kp_name = (json.loads(bytes.fromhex(kp_hex).decode()) or {}).get("name", "")
        except (ValueError, TypeError):
            kp_name = ""
    if kp_name != "tpm":
        raise HTTPException(status_code=403,
                            detail=f"key_provider must be tpm, got '{kp_name or 'unknown'}'")

    # c) compose_hash — FAIL-CLOSED: must be in the runtime-managed GLOBAL KMS
    #    compose whitelist (POST/DELETE /api/v1/admin/kms-compose-hashes), or the
    #    user's own allowed_kms_compose_hashes (back-compat). No trust-on-first-use.
    if not compose_hash:
        raise HTTPException(status_code=403, detail="compose_hash missing from attestation")
    allowed_compose = store.get_kms_compose_hashes() + \
        [h.lower() for h in (user.get("allowed_kms_compose_hashes") or [])]
    if not allowed_compose:
        raise HTTPException(status_code=403,
                            detail="no approved KMS compose_hash (fail-closed; add one via "
                                   "POST /api/v1/admin/kms-compose-hashes)")
    if compose_hash not in allowed_compose:
        raise HTTPException(status_code=403, detail="compose_hash not in KMS whitelist")
    logger.info("provision %s: KMS whitelist OK (os_image_hash✓ key_provider=tpm✓ compose_hash✓)", user_id)


@app.post("/api/v1/challenge", response_model=ChallengeResponse)
def challenge(req: ChallengeRequest, authorization: Optional[str] = Header(None)):
    """Issue a stateless (HMAC) challenge nonce for the courier attest flow."""
    user_id = resolve_user(req.user_id, authorization)  # authenticates caller
    nonce = issue_challenge(user_id)
    return ChallengeResponse(nonce=nonce, authority_ts=int(time.time()))


@app.post("/api/v1/measure")
def measure(req: MeasureRequest, authorization: Optional[str] = Header(None)):
    """Read-only measurement discovery. Verifies the quote's authenticity and
    returns the MEASURED values (os_image_hash, compose_hash, key_provider, …)
    so an operator can learn EXPECTED_OS_IMAGE_HASH for a new OS image. Releases
    NO root key and enforces NO whitelist — it is purely informational, so it is
    safe to run before anything is pinned (unlike a provision bypass)."""
    require_admin(authorization)
    attestation = (req.attestation or "").strip()
    if not attestation:
        raise HTTPException(status_code=400, detail="attestation required")
    try:
        # NB: do NOT inject EXPECTED_OS_IMAGE_HASH — we are discovering it.
        result = verify_attestation(VERIFIER_URL, attestation, req.vm_config)
    except VerifierError as e:
        raise HTTPException(status_code=502, detail=str(e))
    details = result.get("details", {})
    if not details.get("quote_verified"):
        raise HTTPException(status_code=403, detail=f"quote not authentic: {result.get('reason')}")
    app_info = details.get("app_info") or {}
    kp_name = ""
    kp_hex = app_info.get("key_provider_info") or ""
    if kp_hex:
        try:
            kp_name = (json.loads(bytes.fromhex(kp_hex).decode()) or {}).get("name", "")
        except (ValueError, TypeError):
            kp_name = ""
    return {
        "quote_verified": True,
        "tcb_status": details.get("tcb_status"),
        "os_image_hash": app_info.get("os_image_hash"),
        "compose_hash": app_info.get("compose_hash"),
        "mr_aggregated": app_info.get("mr_aggregated"),
        "key_provider": kp_name,
    }


@app.post("/api/v1/provision", response_model=ProvisionResponse)
def provision(req: ProvisionRequest, authorization: Optional[str] = Header(None)):
    """Verify the TDX quote and return a sealed root key + AuthBundle.

    P0 implementation — skips real quote verification and HPKE encryption.
    Each TODO marks where production hardening is required.
    """
    user_id = resolve_user(req.user_id, authorization)

    # validate the stateless challenge nonce (authentic MAC, within TTL, bound
    # to this customer). NB: stateless ⇒ replay-within-window is possible; see
    # crypto.issue_challenge — the TDX-quote binding is the real anti-replay.
    if not verify_challenge(req.nonce, user_id):
        raise HTTPException(status_code=400, detail="invalid or expired nonce")

    # sanity-check clock skew between authority and KMS instance
    skew = abs(req.kms_ts - int(time.time()))
    if skew > 300:
        raise HTTPException(status_code=400, detail=f"kms clock skew too large: {skew}s")

    # this user's own (independently-generated) root key material
    user = store.get_or_create_user(user_id)

    # verify the KMS TDX attestation (delegates to dstack-verifier) and that the
    # quote is bound to this transport key — BEFORE sealing the root to it.
    verify_kms_attestation(req, user_id, user)
    kms_k256_pubkey = ""
    root_material = user["root_material"]
    # KMS rpc cert domain — must be a name the workloads can resolve AND that
    # matches kms_urls (else RA-TLS hostname verification fails). On GCP use the
    # instance's internal DNS name (auto-resolvable in-VPC). Configurable so the
    # cert isn't pinned to the unroutable default "kms.local".
    kms_domain = os.getenv("KMS_DOMAIN", "kms.local")
    root_payload = make_root_payload(
        root_material["root_ca_key_pem"], root_material["k256_key_b64"], domain=kms_domain
    )

    # HPKE-seal the root to the KMS transport key so the relaying CLI can't read
    # it (RFC 9180: DHKEM-X25519 + HKDF-SHA256 + AES-256-GCM). Only the TEE that
    # holds the transport private key can open it.
    if not req.transport_pub:
        raise HTTPException(status_code=400, detail="transport_pub required")
    sealed_root = seal_root(root_payload, req.transport_pub)

    bundle_seq = store.bump_bundle_seq(user_id)
    auth_bundle = make_auth_bundle(
        user_id, bundle_seq, kms_k256_pubkey,
        app_whitelist=store.get_apps(user_id),
        keyring=store.get_keyring(),       # GLOBAL image keyring (vendor-wide)
        os_images=store.get_os_images(),   # runtime-managed os-image whitelist
    )

    return ProvisionResponse(sealed_root=sealed_root, auth_bundle=auth_bundle)


@app.post("/api/v1/sync-auth", response_model=SyncAuthResponse)
def sync_auth(req: SyncAuthRequest, authorization: Optional[str] = Header(None)):
    """Issue a fresh AuthBundle without re-provisioning the root key.

    Called periodically by the operator to renew authorization (e.g., after
    whitelist updates or near bundle expiry).

    P3 stub: accepts and logs usage_receipt; full reconciliation is TODO.
    """
    user_id = resolve_user(req.user_id, authorization)

    # P3 stub: log usage receipt if provided
    if req.usage_receipt is not None:
        receipt = req.usage_receipt
        active_count = len(receipt.active_slots)
        logger.info(
            "usage_receipt received: user_id=%s bundle_seq=%d active_slots=%d",
            receipt.user_id,
            receipt.bundle_seq,
            active_count,
        )
        # TODO P3: persist receipt, validate kms_sig, run reconciliation / billing

    bundle_seq = store.bump_bundle_seq(user_id)
    auth_bundle = make_auth_bundle(
        user_id, bundle_seq,
        app_whitelist=store.get_apps(user_id),
        keyring=store.get_keyring(),       # GLOBAL image keyring (vendor-wide)
        os_images=store.get_os_images(),   # runtime-managed os-image whitelist
    )
    return SyncAuthResponse(auth_bundle=auth_bundle)


# ─── admin endpoints (multi-user management) ──────────────────────────────────

@app.post("/api/v1/admin/users", response_model=CreateUserResponse)
def create_user(req: CreateUserRequest, _: None = Depends(require_admin)):
    """Create a user with its own independently-generated root key.

    Returns the API key in plaintext exactly once — hand it to that customer's
    operator, who passes it as `Authorization: Bearer <api_key>`.
    """
    try:
        api_key = store.create_user(req.user_id, req.name or "")
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("created user user_id=%s", req.user_id)
    return CreateUserResponse(user_id=req.user_id, api_key=api_key)


@app.post("/api/v1/admin/users/{user_id}/images")
def register_image(user_id: str, req: RegisterImageRequest, _: None = Depends(require_admin)):
    """Register a real workload app + encrypted-image CEK for a user. The next
    provision/sync-auth emits this in the AuthBundle's app_whitelist (replacing
    the dev placeholder). Returns the app entry incl. the CEK."""
    app = store.register_app_image(
        user_id, req.app_id, req.allowed_launcher_digests, req.image_digest, req.cek or ""
    )
    logger.info("registered image for %s app=%s digest=%s", user_id, req.app_id, req.image_digest)
    return {"app": app}


@app.post("/api/v1/admin/keys", response_model=MintKeyResponse)
def mint_key(req: MintKeyRequest, _: None = Depends(require_admin)):
    """Mint a long-lived image keypair (kid → EC P-256) into the GLOBAL keyring.
    The keyring is vendor-wide (not per-user): every tenant's next
    provision/sync-auth carries its PRIVATE keys in the AuthBundle (leased to
    attested launchers), so one encrypted image artifact decrypts everywhere.
    Returns the PUBLIC key — encrypt images to it with
    `skopeo copy --encryption-key jwe:<pub.pem>`. The private key is never
    returned by the API."""
    try:
        entry = store.mint_key(req.kid or "", req.not_after or 0)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("minted global image key kid=%s", entry["kid"])
    return MintKeyResponse(**entry)


@app.get("/api/v1/admin/keys")
def list_keys(_: None = Depends(require_admin)):
    """List the global keyring (kid + public key; private keys are never echoed)."""
    ring = store.get_keyring()
    return {"keys": [{k: v for k, v in e.items() if k != "priv_pem"} for e in ring]}


@app.delete("/api/v1/admin/keys/{kid}")
def revoke_key(kid: str, _: None = Depends(require_admin)):
    """Revoke a kid from the global keyring. Images encrypted with it must be
    re-encrypted under a live kid and re-shipped; effective on the next
    provision/sync-auth for every tenant."""
    removed = store.revoke_key(kid)
    if not removed:
        raise HTTPException(status_code=404, detail=f"kid not found: {kid}")
    logger.info("revoked global image key kid=%s", kid)
    return {"revoked": kid}


# ─── runtime attestation policy: allowed OS-image & KMS-compose hashes ────────
# Manage the whitelists live (no restart). Enforced fail-closed in
# verify_kms_attestation; os-images also flow into every AuthBundle.

@app.post("/api/v1/admin/os-images")
def add_os_image(req: HashRequest, _: None = Depends(require_admin)):
    """Approve an OS-image hash (discover it with `kms_ctl.py measure`)."""
    try:
        lst = store.add_os_image(req.hash)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.info("approved os_image hash %s", req.hash)
    return {"os_images": lst}


@app.get("/api/v1/admin/os-images")
def list_os_images(_: None = Depends(require_admin)):
    return {"os_images": store.get_os_images()}


@app.delete("/api/v1/admin/os-images/{h}")
def remove_os_image(h: str, _: None = Depends(require_admin)):
    if not store.remove_os_image(h):
        raise HTTPException(status_code=404, detail=f"os_image hash not found: {h}")
    logger.info("removed os_image hash %s", h)
    return {"os_images": store.get_os_images()}


@app.post("/api/v1/admin/kms-compose-hashes")
def add_kms_compose_hash(req: HashRequest, _: None = Depends(require_admin)):
    """Approve a KMS compose_hash (the key-broker+dstack-kms stack)."""
    try:
        lst = store.add_kms_compose_hash(req.hash)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.info("approved kms compose_hash %s", req.hash)
    return {"kms_compose_hashes": lst}


@app.get("/api/v1/admin/kms-compose-hashes")
def list_kms_compose_hashes(_: None = Depends(require_admin)):
    return {"kms_compose_hashes": store.get_kms_compose_hashes()}


@app.delete("/api/v1/admin/kms-compose-hashes/{h}")
def remove_kms_compose_hash(h: str, _: None = Depends(require_admin)):
    if not store.remove_kms_compose_hash(h):
        raise HTTPException(status_code=404, detail=f"kms compose_hash not found: {h}")
    logger.info("removed kms compose_hash %s", h)
    return {"kms_compose_hashes": store.get_kms_compose_hashes()}


# ─── per-app digest whitelists: launcher (compose_hash) + workload (payload) ──
# Both gate the key-broker lease: the attested compose_hash must be in
# allowed_launcher_digests, and the requested image digest in
# allowed_workload_digests. Manage either live ("*" = wildcard, dev only).

_DIGEST_FIELDS = {
    "launcher-digests": "allowed_launcher_digests",
    "workload-digests": "allowed_workload_digests",
}


def _digest_field(kind: str) -> str:
    f = _DIGEST_FIELDS.get(kind)
    if not f:
        raise HTTPException(status_code=404, detail=f"unknown digest list: {kind}")
    return f


@app.post("/api/v1/admin/users/{user_id}/apps/{app_id}/{kind}")
def add_app_digest(user_id: str, app_id: str, kind: str, req: HashRequest,
                   _: None = Depends(require_admin)):
    field = _digest_field(kind)
    try:
        return {field: store.add_app_digest(user_id, app_id, field, req.hash)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/admin/users/{user_id}/apps/{app_id}/{kind}")
def list_app_digests(user_id: str, app_id: str, kind: str, _: None = Depends(require_admin)):
    field = _digest_field(kind)
    try:
        return {field: store.get_app_digests(user_id, app_id, field)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/admin/users/{user_id}/apps/{app_id}/{kind}/{h}")
def remove_app_digest(user_id: str, app_id: str, kind: str, h: str,
                      _: None = Depends(require_admin)):
    field = _digest_field(kind)
    try:
        return {field: store.remove_app_digest(user_id, app_id, field, h)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/admin/users", response_model=ListUsersResponse)
def list_users(_: None = Depends(require_admin)):
    """List all users (metadata only; no keys or root material)."""
    return ListUsersResponse(users=[UserInfo(**u) for u in store.list_users()])


@app.post("/api/v1/admin/users/{user_id}/rotate-key", response_model=CreateUserResponse)
def rotate_user_key(user_id: str, _: None = Depends(require_admin)):
    """Issue a fresh API key for a user (the root key is unchanged)."""
    try:
        api_key = store.rotate_api_key(user_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return CreateUserResponse(user_id=user_id, api_key=api_key)


@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(user_id: str, _: None = Depends(require_admin)):
    """Delete a user and its root key material."""
    if not store.delete_user(user_id):
        raise HTTPException(status_code=404, detail=f"unknown user: {user_id}")
    return {"deleted": user_id}
