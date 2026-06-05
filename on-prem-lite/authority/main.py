# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""on-prem-lite vendor authority (KMS-less, license-based).

Issues a per-workload {sealed_cek, License} to an attested launcher CVM:
verifies the launcher's TDX+vTPM quote via dstack-verifier (fail-closed gates),
HPKE-seals the image private key (CEK) to the launcher's transport key, and
Ed25519-signs a License with an expiry. See on-prem-lite/DESIGN.md for the wire
contract; a Rust launcher verifies the License signature and HPKE-opens the CEK.
"""

import base64
import json
import logging
import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException

from crypto import (
    get_authority_pubkey_bytes,
    issue_challenge,
    seal_cek,
    sign_license,
    verify_challenge,
)
from models import (
    ChallengeRequest,
    ChallengeResponse,
    CreateAppRequest,
    CreateAppResponse,
    CreateTenantRequest,
    CreateTenantResponse,
    HashRequest,
    LicenseRequest,
    LicenseResponse,
    MintKeyRequest,
    MintKeyResponse,
    RegisterWorkloadRequest,
)
from store import Store
from verifier_client import VerifierError, compute_report_data, verify_attestation

logger = logging.getLogger(__name__)

app = FastAPI(title="dstack on-prem-lite authority", version="0.1.0")
store = Store()

# ─── auth ─────────────────────────────────────────────────────────────────────
# admin endpoints are gated by AUTHORITY_ADMIN_TOKEN; operator endpoints
# (challenge / license) require a per-tenant bearer API key. The admin token is
# REQUIRED — without it the authority refuses to serve (fail-closed): there is no
# open/dev mode in this profile.
ADMIN_TOKEN = os.getenv("AUTHORITY_ADMIN_TOKEN", "")

# Attestation verification via the repo's dstack-verifier service. A license is
# ALWAYS issued against a verified quote — there is no no-attestation bypass.
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://verifier:8080")
ALLOWED_TCB_STATUSES = {
    s.strip() for s in os.getenv("ALLOWED_TCB_STATUSES", "UpToDate,SWHardeningNeeded").split(",") if s.strip()
}
# License expiry policy.
LICENSE_TTL_SECS = int(os.getenv("LICENSE_TTL_SECS", str(86400 * 30)))   # 30d
LICENSE_GRACE_SECS = int(os.getenv("LICENSE_GRACE_SECS", "300"))

if not ADMIN_TOKEN:
    logger.warning("AUTHORITY_ADMIN_TOKEN unset — admin + operator endpoints are FAIL-CLOSED "
                   "(refused with 503) until it is set")


def _bearer(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


def require_admin(authorization: Optional[str] = Header(None)) -> None:
    """Gate admin endpoints behind the authority admin token. FAIL-CLOSED: if no
    token is configured, admin endpoints are refused (no open/dev mode)."""
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503,
                            detail="authority admin token not configured (fail-closed); set AUTHORITY_ADMIN_TOKEN")
    import hmac
    if not hmac.compare_digest(_bearer(authorization), ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="invalid admin token")


def resolve_tenant(req_user_id: str, authorization: Optional[str]) -> str:
    """Resolve the calling tenant from its bearer API key. The request's user_id,
    if given, must match the authenticated tenant (strict isolation). FAIL-CLOSED:
    a tenant API key is always required (no token ⇒ refuse; no dev trust-user_id)."""
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503,
                            detail="authority not configured for tenants (fail-closed); set AUTHORITY_ADMIN_TOKEN")
    tid = store.find_tenant_by_api_key(_bearer(authorization))
    if tid is None:
        raise HTTPException(status_code=401, detail="invalid or missing api key")
    if req_user_id and req_user_id != tid:
        raise HTTPException(
            status_code=403,
            detail=f"user_id '{req_user_id}' does not match authenticated tenant '{tid}'",
        )
    return tid


@app.get("/api/v1/authority-pubkey")
def authority_pubkey():
    """Return the authority Ed25519 public key.

    The vendor pins this into the measured launcher compose (AUTHORITY_PUBKEY)
    so the launcher can verify License signatures offline.
    """
    return {"pubkey": base64.b64encode(get_authority_pubkey_bytes()).decode()}


@app.post("/api/v1/challenge", response_model=ChallengeResponse)
def challenge(req: ChallengeRequest, authorization: Optional[str] = Header(None)):
    """Issue a stateless (HMAC) challenge nonce for the courier attest flow."""
    tenant_id = resolve_tenant(req.user_id, authorization)  # authenticates caller
    nonce = issue_challenge(tenant_id)
    return ChallengeResponse(nonce=nonce, authority_ts=int(time.time()))


def _verify_launcher_attestation(req: LicenseRequest, tenant_id: str) -> tuple:
    """Verify the launcher's TDX+vTPM attestation and enforce the fail-closed
    gates G1–G6b. Returns (attested_app_id, attested_compose_hash), both
    lowercased. Raises HTTPException on any policy failure.
    """
    # FAIL-CLOSED: an attestation is always required — there is no dev/no-quote
    # bypass. A license is only ever issued against a verified TDX+vTPM quote.
    attestation = (req.attestation or "").strip()
    if not attestation:
        raise HTTPException(status_code=400, detail="attestation required (fail-closed)")

    # os-image whitelist is FAIL-CLOSED (G4, enforced below). When exactly one is
    # configured, inject it into vm_config so the verifier can pin it; with
    # several, the membership check below is the gate.
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
    app_info = details.get("app_info") or {}
    logger.info(
        "verifier[%s]: is_valid=%s quote=%s eventlog=%s os_image=%s tcb=%s "
        "compose=%s app_id=%s kp_info=%s reason=%s",
        tenant_id, result.get("is_valid"), details.get("quote_verified"),
        details.get("event_log_verified"), details.get("os_image_hash_verified"),
        details.get("tcb_status"), app_info.get("compose_hash"),
        app_info.get("app_id"), app_info.get("key_provider_info"), result.get("reason"),
    )

    # G1: the TDX(+vTPM) quote must be authentic (hardware-rooted).
    if not details.get("quote_verified"):
        raise HTTPException(status_code=403, detail=f"quote verification failed: {result.get('reason')}")

    # G2: report_data must bind this session's transport key/nonce (anti-substitution).
    expected = compute_report_data(req.nonce, req.transport_pub, req.kms_ts).hex()
    got = (details.get("report_data") or "").lower()
    if got != expected.lower():
        raise HTTPException(status_code=403,
                            detail="report_data mismatch: quote not bound to this transport key/nonce")

    # G3: TCB status must be acceptable (empty/missing ⇒ deny).
    tcb = details.get("tcb_status")
    if tcb not in ALLOWED_TCB_STATUSES:
        raise HTTPException(status_code=403, detail=f"unacceptable tcb_status: {tcb}")

    # G4: os-image hash — FAIL-CLOSED (empty whitelist ⇒ deny). Register the
    # vendor-approved os_image_hash via POST /api/v1/admin/os-images (the vendor
    # reads it from the OS release's auth_hash.txt; vendor-release.sh does this).
    if not allowed_os:
        raise HTTPException(status_code=403,
                            detail="no approved os_image_hash (fail-closed; register one via "
                                   "POST /api/v1/admin/os-images)")
    if not details.get("os_image_hash_verified"):
        raise HTTPException(status_code=403,
                            detail=f"os_image_hash not verified: {result.get('reason')}")
    os_hash = (app_info.get("os_image_hash") or "").lower()
    if os_hash not in allowed_os:
        raise HTTPException(status_code=403,
                            detail=f"os_image_hash not in whitelist: {os_hash or 'none'}")

    # G5: key_provider must be tpm (vTPM-sealed disk). key_provider_info is the
    # hex of JSON {"name": "<none|local-sgx|tpm|kms>", "id": "<pubkey>"}.
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

    # G6: launcher compose_hash ∈ the runtime-managed whitelist (fail-closed: empty ⇒ deny).
    compose_hash = (app_info.get("compose_hash") or "").lower()
    if not compose_hash:
        raise HTTPException(status_code=403, detail="compose_hash missing from attestation")
    allowed_compose = store.get_launcher_compose_hashes()
    if not allowed_compose:
        raise HTTPException(status_code=403,
                            detail="no approved launcher compose_hash (fail-closed; add one via "
                                   "POST /api/v1/admin/launcher-compose-hashes)")
    if compose_hash not in allowed_compose:
        raise HTTPException(status_code=403, detail="compose_hash not in launcher whitelist")

    # G6b: app_id. NOTE on the `key_provider=tpm` profile the attested app_id is
    # DERIVED from compose_hash (= compose_hash[:40]); it is NOT an independently
    # settable measured value (that requires the KMS/on-chain registry, which the
    # lite profile drops). So app_id here is an authority-side LABEL — the operator
    # names the app it is deploying, and we require that app to be REGISTERED under
    # this tenant (and gate the workload digest against THAT app's whitelist below).
    # The *measured* identity is compose_hash (G6, enforced above). We record the
    # attested (compose-derived) app_id for audit but don't compare it to the label.
    attested_app_id = (app_info.get("app_id") or "").lower()
    req_app_id = (req.app_id or "").lower()
    if not req_app_id:
        raise HTTPException(status_code=403, detail="app_id (label) required")
    if not store.is_registered_app(tenant_id, req_app_id):
        raise HTTPException(status_code=403,
                            detail=f"app_id not registered under tenant: {req_app_id}")

    logger.info("license %s: gates OK (quote✓ report_data✓ tcb✓ key_provider=tpm✓ "
                "compose_hash✓ app_label=%s attested_app_id=%s)",
                tenant_id, req_app_id, attested_app_id)
    return req_app_id, compose_hash


@app.post("/api/v1/license", response_model=LicenseResponse)
def license(req: LicenseRequest, authorization: Optional[str] = Header(None)):
    """Verify the launcher attestation and return a {sealed_cek, signed License}.

    The core endpoint: gates G1–G7 (fail-closed), then HPKE-seals the image
    private key (CEK) to the launcher transport key and Ed25519-signs a License
    with a monotonic seq + expiry.
    """
    tenant_id = resolve_tenant(req.user_id, authorization)

    # validate the stateless challenge nonce (authentic MAC, within TTL, bound to
    # this tenant). The TDX-quote report_data binding is the real anti-replay.
    if not verify_challenge(req.nonce, tenant_id):
        raise HTTPException(status_code=400, detail="invalid or expired nonce")

    # clock-skew guard between authority and launcher.
    skew = abs(req.kms_ts - int(time.time()))
    if skew > 300:
        raise HTTPException(status_code=400, detail=f"clock skew too large: {skew}s")

    if not req.transport_pub:
        raise HTTPException(status_code=400, detail="transport_pub required")
    if not req.workload_digest:
        raise HTTPException(status_code=400, detail="workload_digest required")

    # G1–G6b: verify attestation; returns the validated app_id + the launcher's
    # measured compose_hash (bound into the License so the launcher can check it
    # equals its own).
    app_id, attested_compose_hash = _verify_launcher_attestation(req, tenant_id)

    # G7: requested workload_digest ∈ this app's allowed_workloads (fail-closed:
    # empty ⇒ deny). The matched entry carries the kid → image keypair.
    workload = store.find_allowed_workload(tenant_id, app_id, req.workload_digest)
    if workload is None:
        raise HTTPException(status_code=403,
                            detail=f"workload_digest not allowed for app {app_id}: {req.workload_digest}")

    # look up the image keypair for that workload's kid; HPKE-seal its PRIVATE
    # key PEM (the CEK) to the launcher transport key.
    kid = workload.get("kid", "")
    key_entry = store.get_key(kid)
    if key_entry is None:
        raise HTTPException(status_code=500, detail=f"image key not found for kid: {kid}")
    sealed_cek = seal_cek(key_entry["priv_pem"], req.transport_pub)

    # build + Ed25519-sign the License.
    now = int(time.time())
    ttl = store.license_ttl(tenant_id, LICENSE_TTL_SECS)
    seq = store.bump_license_seq(tenant_id, app_id)
    license_obj = {
        "schema_version": 1,
        "license_id": f"{tenant_id}-{seq}",
        "tenant_id": tenant_id,
        "app_id": app_id,
        # the launcher's measured compose (which launcher build). Empty only in
        # the dev no-attestation path; the launcher additionally checks
        # license.compose_hash == its own.
        "compose_hash": attested_compose_hash,
        "workload": {
            "image": workload.get("image", ""),
            "digest": workload.get("digest", req.workload_digest),
            "kid": kid,
        },
        "seq": seq,
        "issued_at": now,
        "not_before": now,
        "expires_at": now + ttl,
        "grace_period_secs": LICENSE_GRACE_SECS,
    }
    license_obj["authority_sig"] = sign_license(license_obj)

    logger.info("issued license %s seq=%d app=%s digest=%s kid=%s expires_at=%d",
                license_obj["license_id"], seq, app_id, req.workload_digest, kid,
                license_obj["expires_at"])
    return LicenseResponse(license=license_obj, sealed_cek=sealed_cek)


# ─── admin: tenants & apps ────────────────────────────────────────────────────

@app.post("/api/v1/admin/tenants", response_model=CreateTenantResponse)
def create_tenant(req: CreateTenantRequest, _: None = Depends(require_admin)):
    """Create a tenant. Returns the API key in plaintext exactly once."""
    try:
        api_key = store.create_tenant(req.tenant_id, req.name or "")
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("created tenant tenant_id=%s", req.tenant_id)
    return CreateTenantResponse(tenant_id=req.tenant_id, api_key=api_key)


@app.post("/api/v1/admin/tenants/{tid}/apps", response_model=CreateAppResponse)
def create_app(tid: str, req: CreateAppRequest, _: None = Depends(require_admin)):
    """Register an app under a tenant (authority assigns a 40-hex app_id if omitted)."""
    try:
        app_id = store.create_app(tid, (req.app_id or "").strip(), req.name or "")
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("created app tenant=%s app_id=%s", tid, app_id)
    return CreateAppResponse(app_id=app_id)


@app.post("/api/v1/admin/tenants/{tid}/apps/{app_id}/workloads")
def register_workload(tid: str, app_id: str, req: RegisterWorkloadRequest,
                      _: None = Depends(require_admin)):
    """Append (image,digest,kid) to an app's allowed_workloads + record current."""
    try:
        entry = store.register_workload(tid, app_id, req.image, req.digest, req.kid)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    logger.info("registered workload tenant=%s app=%s digest=%s kid=%s",
                tid, app_id, req.digest, req.kid)
    return {"workload": entry}


# ─── admin: image keys ────────────────────────────────────────────────────────

@app.post("/api/v1/admin/keys", response_model=MintKeyResponse)
def mint_key(req: MintKeyRequest, _: None = Depends(require_admin)):
    """Mint an EC P-256 image keypair into the keystore. Returns the PUBLIC key
    — encrypt images to it with `skopeo copy --encryption-key jwe:<pub.pem>`.
    The private key (the CEK) is never returned by the API."""
    try:
        entry = store.mint_key((req.kid or "").strip())
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    logger.info("minted image key kid=%s", entry["kid"])
    return MintKeyResponse(**entry)


@app.get("/api/v1/admin/keys")
def list_keys(_: None = Depends(require_admin)):
    """List the keystore (kid + public key; private keys are never echoed)."""
    return {"keys": store.list_keys()}


# ─── admin: launcher compose-hash policy (G6) ─────────────────────────────────

@app.post("/api/v1/admin/launcher-compose-hashes")
def add_launcher_compose_hash(req: HashRequest, _: None = Depends(require_admin)):
    """Approve a launcher compose_hash (which launcher build may run)."""
    try:
        lst = store.add_launcher_compose_hash(req.hash)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.info("approved launcher compose_hash %s", req.hash)
    return {"launcher_compose_hashes": lst}


@app.get("/api/v1/admin/launcher-compose-hashes")
def list_launcher_compose_hashes(_: None = Depends(require_admin)):
    return {"launcher_compose_hashes": store.get_launcher_compose_hashes()}


@app.delete("/api/v1/admin/launcher-compose-hashes/{h}")
def remove_launcher_compose_hash(h: str, _: None = Depends(require_admin)):
    if not store.remove_launcher_compose_hash(h):
        raise HTTPException(status_code=404, detail=f"launcher compose_hash not found: {h}")
    logger.info("removed launcher compose_hash %s", h)
    return {"launcher_compose_hashes": store.get_launcher_compose_hashes()}


# ─── admin: os-image policy (G4, optional) ────────────────────────────────────

@app.post("/api/v1/admin/os-images")
def add_os_image(req: HashRequest, _: None = Depends(require_admin)):
    """Approve an os-image hash (optional policy; enforced only when non-empty)."""
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
