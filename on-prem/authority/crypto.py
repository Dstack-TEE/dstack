# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import base64
import hashlib
import hmac
import os
import json
import secrets
import time
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _load_or_create_signing_key() -> Ed25519PrivateKey:
    """Authority AuthBundle signing key (Ed25519), PERSISTENT across restarts and
    shareable across workers — so the authority pubkey is stable and key-broker's
    signature verification keeps working.

    Priority:
      1. AUTHORITY_SIGNING_KEY      — 32-byte seed (hex or base64); for HSM/secret
                                     injection or shared multi-worker deployments.
      2. AUTHORITY_SIGNING_KEY_FILE — raw 32-byte seed file (default
                                     ~/.config/authority/signing.key);
                                     generated once and persisted if absent.
    Production: back this with an HSM / KMS-managed key.
    """
    env = os.getenv("AUTHORITY_SIGNING_KEY", "").strip()
    if env:
        try:
            seed = bytes.fromhex(env)
        except ValueError:
            seed = base64.b64decode(env)
        if len(seed) != 32:
            raise ValueError("AUTHORITY_SIGNING_KEY must be a 32-byte seed")
        return Ed25519PrivateKey.from_private_bytes(seed)

    path = os.path.expanduser(
        os.getenv("AUTHORITY_SIGNING_KEY_FILE", "~/.config/authority/signing.key")
    )
    if os.path.exists(path):
        with open(path, "rb") as f:
            return Ed25519PrivateKey.from_private_bytes(f.read())

    key = Ed25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    os.chmod(path, 0o600)
    return key


_AUTHORITY_PRIVATE_KEY: Ed25519PrivateKey = _load_or_create_signing_key()
_AUTHORITY_PUBLIC_KEY = _AUTHORITY_PRIVATE_KEY.public_key()


def get_authority_pubkey_bytes() -> bytes:
    return _AUTHORITY_PUBLIC_KEY.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ─── per-user API keys ────────────────────────────────────────────────────────
# Each authority user authenticates with a bearer API key. Only the SHA-256 hash
# is persisted; the plaintext key is shown once at creation time.

def generate_api_key() -> str:
    """Generate a new opaque user API key (shown once)."""
    return "vp_" + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """SHA-256 hex digest of an API key, for storage and comparison."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def api_key_matches(api_key: str, stored_hash: str) -> bool:
    """Constant-time compare an API key against a stored hash."""
    return hmac.compare_digest(hash_api_key(api_key), stored_hash)


# ─── stateless challenge nonce (HMAC) ─────────────────────────────────────────
# The challenge nonce is a self-contained HMAC token: `<ts>.<rand>.<mac>` where
# mac = HMAC-SHA256(secret, "<ts>.<rand>.<user_id>"). The authority stores
# nothing — it re-derives the MAC and checks the timestamp on use. This makes
# /challenge + /provision stateless (survives restarts, works across workers
# when AUTHORITY_NONCE_SECRET is shared).
#
# Trade-off: a valid token can be REPLAYED within its TTL window (statelessness
# precludes free single-use). The protocol's real anti-replay is binding the
# nonce into the TDX quote report_data (SHA512(nonce||transport_pub||kms_ts));
# once quote verification lands, a replayed nonce still needs a fresh quote.
# The token is also bound to user_id, so it cannot be used by another tenant.

# Shared across workers/replicas only if configured; otherwise per-process random
# (single-process safe, but multi-worker requires AUTHORITY_NONCE_SECRET to be set).
_NONCE_SECRET: bytes = (
    os.getenv("AUTHORITY_NONCE_SECRET", "").encode() or secrets.token_bytes(32)
)
_NONCE_TTL: int = int(os.getenv("AUTHORITY_NONCE_TTL", "300"))


def _challenge_mac(payload: str, user_id: str) -> str:
    msg = f"{payload}.{user_id}".encode()
    digest = hmac.new(_NONCE_SECRET, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def issue_challenge(user_id: str) -> str:
    """Issue a stateless challenge nonce bound to `user_id`."""
    ts = int(time.time())
    rand = secrets.token_urlsafe(16)          # urlsafe → no '.', safe as delimiter
    payload = f"{ts}.{rand}"
    return f"{payload}.{_challenge_mac(payload, user_id)}"


def verify_challenge(token: str, user_id: str) -> bool:
    """Validate a challenge nonce for `user_id`: authentic MAC + within TTL."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    ts_s, rand, mac = parts
    if not hmac.compare_digest(mac, _challenge_mac(f"{ts_s}.{rand}", user_id)):
        return False
    try:
        ts = int(ts_s)
    except ValueError:
        return False
    return 0 <= (int(time.time()) - ts) <= _NONCE_TTL


def sign_auth_bundle(bundle: Dict[str, Any]) -> str:
    """Sign the bundle (excluding authority_sig) with Ed25519; return base64."""
    payload = {k: v for k, v in bundle.items() if k != "authority_sig"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = _AUTHORITY_PRIVATE_KEY.sign(canonical.encode())
    return base64.b64encode(sig).decode()


def generate_root_material() -> dict:
    """Generate the authority-held root key material for one customer.

    dstack-kms derives every app/disk/env key (and the image CEKs) from its
    root CA key via HKDF, and signs identity chains with a separate secp256k1
    key. To let the authority hold the customer's root (enabling DR + CEK
    derivation, per the v2 design), we generate both here and ship them to the
    KMS sidecar, which materialises the full dstack-kms key set on disk.

      - root_ca_key_pem : P-256 (prime256v1) PKCS#8 PEM. MUST be P-256 — the
        KMS KDF extracts the P-256 scalar from this key (ra-tls kdf.rs).
      - k256_key_b64    : secp256k1 32-byte big-endian scalar, base64. Becomes
        dstack-kms `root-k256.key` (k256::ecdsa::SigningKey::from_slice).
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    root_ca_key = ec.generate_private_key(ec.SECP256R1())
    root_ca_key_pem = root_ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    k256_key = ec.generate_private_key(ec.SECP256K1())
    k256_scalar = k256_key.private_numbers().private_value.to_bytes(32, "big")
    k256_key_b64 = base64.b64encode(k256_scalar).decode()

    return {"root_ca_key_pem": root_ca_key_pem, "k256_key_b64": k256_key_b64}


def generate_cek() -> str:
    """Generate a 32-byte CEK, return as base64. (Legacy symmetric per-digest
    path; the keyring now uses asymmetric keypairs — see generate_keypair.)"""
    import secrets as _secrets
    return base64.b64encode(_secrets.token_bytes(32)).decode()


def generate_keypair() -> dict:
    """Generate an EC P-256 keypair for ocicrypt's native JWE (ECDH-ES) scheme.

    Returns {priv_pem, pub_pem}. Images are encrypted to `pub_pem` (public key
    only — the build machine never holds a decryption secret); `priv_pem`
    (PKCS#8) is the secret the authority keeps and leases to attested launchers
    inside the AuthBundle. PKCS#8 because ocicrypt's Go key parser needs it
    (SEC1 `EC PRIVATE KEY` is not accepted)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return {"priv_pem": priv_pem, "pub_pem": pub_pem}


def make_root_payload(root_ca_key_pem: str, k256_key_b64: str,
                      domain: str = "kms.local") -> str:
    """Build the sealed_root payload (JSON) the KMS sidecar expects.

    The sidecar HPKE-opens sealed_root and parses this JSON, then materialises
    the dstack-kms key set (root-ca / tmp-ca / rpc / k256).
    """
    return json.dumps({
        "v": 1,
        "root_ca_key": root_ca_key_pem,
        "k256_key": k256_key_b64,
        "domain": domain,
    })


# ─── HPKE sealing of the root payload to the KMS transport key ────────────────
# RFC 9180 HPKE, base mode, suite:
#   KEM  = DHKEM(X25519, HKDF-SHA256)
#   KDF  = HKDF-SHA256
#   AEAD = AES-256-GCM
# The KMS sidecar (key-broker) generates an X25519 transport keypair per courier
# session and returns the public key (transport_pub). We seal the root payload
# to it: only the holder of the transport private key (inside the TEE) can open
# it, so the untrusted CLI relaying the blob cannot read the root.
#
# Wire format of sealed_root: base64( enc(32 bytes) || ciphertext ), matching
# the key-broker's `unseal_root`.
HPKE_INFO = b"dstack-courier-root-v1"


def seal_root(root_payload: str, transport_pub_b64: str) -> str:
    """HPKE-seal the root payload to the KMS transport public key."""
    from pyhpke import AEADId, CipherSuite, KDFId, KEMId

    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
    )
    pub_raw = base64.b64decode(transport_pub_b64)
    pkr = suite.kem.deserialize_public_key(pub_raw)
    enc, sender = suite.create_sender_context(pkr, info=HPKE_INFO)
    ct = sender.seal(root_payload.encode(), aad=b"")
    return base64.b64encode(enc + ct).decode()


def make_auth_bundle(user_id: str, bundle_seq: int,
                     kms_k256_pubkey: str = "",
                     app_whitelist: Optional[list] = None,
                     kms_identity: Optional[Dict[str, Any]] = None,
                     keyring: Optional[list] = None,
                     os_images: Optional[list] = None) -> Dict[str, Any]:
    """Build and sign an AuthBundle for a user.

    `app_whitelist` is the user's REAL registered apps (store.get_apps): each
    `{app_id, allowed_launcher_hashes, current_image_digest}` — the entitlement
    gates (which app + compose may run). `keyring` (store.get_keyring) is the
    GLOBAL, vendor-wide image keypairs `[{kid, priv_pem, pub_pem, created_at[,
    not_after]}]` — the SAME keyring goes into every tenant's bundle, so one
    encrypted image decrypts everywhere. Images are encrypted to the PUBLIC key
    (ocicrypt native JWE); the PRIVATE keys are leased to an authorized launcher,
    which passes them all to skopeo, and ocicrypt decrypts with whichever one is
    the image's recipient. Per-user isolation is in root_material, not here.
    *Entitlement* (who gets the keyring) is the app/compose/os attestation here.
    """
    now = int(time.time())
    # FAIL-CLOSED: no registered apps ⇒ authorize nothing (empty whitelist).
    # Register apps via POST /api/v1/admin/users/<id>/images. (No dev placeholder.)
    if not app_whitelist:
        app_whitelist = []
    if not keyring:
        keyring = []

    # GCP doesn't pin device_id, so device binding is explicitly disabled here
    # (an intentional, visible choice — not a silent empty-list default).
    for a in app_whitelist:
        a.setdefault("allow_any_device", True)

    # OS-image whitelist the key-broker enforces fail-closed (bootAuth + lease).
    # Comes from the runtime-managed policy (store.get_os_images()); fall back to
    # the legacy env var only when the caller passes nothing.
    if os_images is None:
        env_os = os.getenv("EXPECTED_OS_IMAGE_HASH", "").strip()
        os_images = [env_os] if env_os else []
    os_images = [h.lower() for h in os_images]
    allowed_tcb = [s.strip() for s in
                   os.getenv("ALLOWED_TCB_STATUSES", "UpToDate,SWHardeningNeeded").split(",")
                   if s.strip()]

    identity = kms_identity or {"expected_mrtd": [], "expected_rtmr": []}
    identity.setdefault("k256_pubkey", kms_k256_pubkey)
    bundle: Dict[str, Any] = {
        "schema_version": 1,
        "user_id": user_id,
        "bundle_seq": bundle_seq,
        "issued_at": now,
        "expires_at": now + 86400 * 30,  # 30 days
        "kms_identity": identity,
        "app_whitelist": app_whitelist,
        "keyring": keyring,                     # GLOBAL [{kid, priv_pem, pub_pem, ...}] leased to launchers
        "os_images": os_images,                 # fail-closed if empty (set EXPECTED_OS_IMAGE_HASH)
        "allowed_tcb_statuses": allowed_tcb,
        "kms": {"allow_any_device": True},      # GCP device_id not pinned (explicit)
        "slot_quota": int(os.getenv("DEMO_SLOT_QUOTA", "5")),
        "revocations": {
            "launcher_hashes": [],
            "image_digests": [],
            "slot_ids": [],
        },
    }
    bundle["authority_sig"] = sign_auth_bundle(bundle)
    return bundle
