# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""Crypto conventions for the on-prem-lite authority.

Forked from on-prem/authority/crypto.py, trimmed for the KMS-less profile:
no KMS root material; the authority signs Licenses (Ed25519) and HPKE-seals a
per-image CEK (the image private key PEM) to the launcher's transport key.

The Ed25519 canonical-JSON signing convention and the HPKE suite are IDENTICAL
to on-prem so a Rust launcher interops byte-for-byte. The ONLY HPKE difference
is the `info` string (b"dstack-lite-cek-v1" instead of b"dstack-courier-root-v1").
"""

import base64
import hashlib
import hmac
import os
import json
import secrets
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _load_or_create_signing_key() -> Ed25519PrivateKey:
    """Authority License-signing key (Ed25519), PERSISTENT across restarts and
    shareable across workers — so the authority pubkey is stable and the
    launcher's signature verification keeps working (the pubkey is measured into
    the launcher compose).

    Priority:
      1. AUTHORITY_SIGNING_KEY      — 32-byte seed (hex or base64); for HSM/secret
                                     injection or shared multi-worker deployments.
      2. AUTHORITY_SIGNING_KEY_FILE — raw 32-byte seed file (default
                                     ~/.config/authority-lite/signing.key);
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
        os.getenv("AUTHORITY_SIGNING_KEY_FILE", "~/.config/authority-lite/signing.key")
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


# ─── per-tenant API keys ──────────────────────────────────────────────────────
# Each authority tenant authenticates with a bearer API key. Only the SHA-256
# hash is persisted; the plaintext key is shown once at creation time.

def generate_api_key() -> str:
    """Generate a new opaque tenant API key (shown once)."""
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
# /challenge + /license stateless (survives restarts, works across workers
# when AUTHORITY_NONCE_SECRET is shared).
#
# Trade-off: a valid token can be REPLAYED within its TTL window (statelessness
# precludes free single-use). The protocol's real anti-replay is binding the
# nonce into the TDX quote report_data (SHA512(nonce||transport_pub||kms_ts));
# a replayed nonce still needs a fresh quote. The token is also bound to user_id,
# so it cannot be used by another tenant.

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


def sign_license(license_obj: Dict[str, Any]) -> str:
    """Sign the License (excluding authority_sig) with Ed25519; return base64.

    Canonical JSON: keys sorted recursively, compact separators — IDENTICAL to
    on-prem crypto.sign_auth_bundle, so the Rust launcher's verifier interops.
    authority_sig = base64( ed25519_sign( canonical_json(license WITHOUT authority_sig) ) ).
    """
    payload = {k: v for k, v in license_obj.items() if k != "authority_sig"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = _AUTHORITY_PRIVATE_KEY.sign(canonical.encode())
    return base64.b64encode(sig).decode()


def generate_keypair() -> dict:
    """Generate an EC P-256 keypair for ocicrypt's native JWE (ECDH-ES) scheme.

    Returns {priv_pem, pub_pem}. Images are encrypted to `pub_pem` (public key
    only — the build machine never holds a decryption secret); `priv_pem`
    (PKCS#8) is the secret the authority keeps and HPKE-seals (as the CEK) to an
    attested launcher's transport key. PKCS#8 because ocicrypt's Go key parser
    needs it (SEC1 `EC PRIVATE KEY` is not accepted)."""
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


# ─── HPKE sealing of the CEK to the launcher transport key ────────────────────
# RFC 9180 HPKE, base mode, suite (IDENTICAL to on-prem seal_root):
#   KEM  = DHKEM(X25519, HKDF-SHA256)
#   KDF  = HKDF-SHA256
#   AEAD = AES-256-GCM
# The launcher generates an X25519 transport keypair per courier session and
# returns the public key (transport_pub). We seal the image PRIVATE key PEM (the
# CEK) to it: only the holder of the transport private key (inside the TEE) can
# open it, so the untrusted CLI relaying the blob cannot read the CEK.
#
# Wire format of sealed_cek: base64( enc(32 bytes) || ciphertext ), aad=b"".
# This is EXACTLY on-prem seal_root but with the lite `info` string.
HPKE_INFO = b"dstack-lite-cek-v1"


def seal_cek(cek_pem: str, transport_pub_b64: str) -> str:
    """HPKE-seal the image private key PEM (the CEK) to the launcher transport key."""
    from pyhpke import AEADId, CipherSuite, KDFId, KEMId

    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
    )
    pub_raw = base64.b64decode(transport_pub_b64)
    pkr = suite.kem.deserialize_public_key(pub_raw)
    enc, sender = suite.create_sender_context(pkr, info=HPKE_INFO)
    ct = sender.seal(cek_pem.encode(), aad=b"")
    return base64.b64encode(enc + ct).decode()
