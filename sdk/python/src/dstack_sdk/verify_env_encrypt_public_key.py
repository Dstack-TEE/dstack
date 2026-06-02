# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Verify ECDSA signatures on KMS env-encrypt public keys.

The KMS signs the X25519 env-encrypt public key it returns from
``/GetAppEnvEncryptPubKey`` so deployers can prove the key originated from a
specific signer before encrypting secrets against it. There are two message
formats:

- ``signature_v1`` (preferred): includes a Unix timestamp to bound replay.
- legacy: pubkey + app_id only. Kept for backward compatibility with old KMS
  builds. Vulnerable to replay; use the v1 variant whenever available.

Both formats sign ``keccak256(prefix + b":" + app_id + [timestamp_be_bytes] +
public_key)`` with secp256k1, producing a 65-byte ``r || s || recovery_id``
signature. This module recovers the signer's compressed public key.
"""

import time
from typing import Optional
import warnings

from eth_keys import keys
from eth_utils import keccak

DEFAULT_MAX_AGE_SECONDS = 300
_PREFIX = b"dstack-env-encrypt-pubkey"
_SEPARATOR = b":"
_FUTURE_SKEW_TOLERANCE_SECONDS = 60


def _normalize_app_id(app_id: str) -> Optional[bytes]:
    if app_id.startswith("0x"):
        app_id = app_id[2:]
    try:
        return bytes.fromhex(app_id)
    except ValueError:
        return None


def _recover_signer(msg_hash: bytes, signature: bytes) -> Optional[str]:
    try:
        recovered = keys.Signature(
            signature_bytes=signature
        ).recover_public_key_from_msg_hash(msg_hash)
        return "0x" + recovered.to_compressed_bytes().hex()
    except Exception:
        return None


def verify_env_encrypt_public_key(
    public_key: bytes,
    signature: bytes,
    app_id: str,
    timestamp: int,
    *,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> Optional[str]:
    """Verify a timestamp-protected KMS env-encrypt public key signature.

    Returns the signer's compressed secp256k1 public key (0x-prefixed hex) on
    success, or ``None`` on bad signature length, expired/future timestamp,
    invalid hex app_id, or signature recovery failure.
    """
    if len(signature) != 65:
        return None

    now = int(time.time())
    age = now - timestamp
    if age < -_FUTURE_SKEW_TOLERANCE_SECONDS:
        return None
    if age > max_age_seconds:
        return None

    app_id_bytes = _normalize_app_id(app_id)
    if app_id_bytes is None:
        return None

    timestamp_bytes = timestamp.to_bytes(8, "big")
    message = _PREFIX + _SEPARATOR + app_id_bytes + timestamp_bytes + public_key
    return _recover_signer(keccak(message), signature)


def verify_env_encrypt_public_key_legacy(
    public_key: bytes,
    signature: bytes,
    app_id: str,
) -> Optional[str]:
    """Verify a legacy (non-timestamped) KMS signature.

    .. deprecated::
        Legacy signatures do not protect against replay attacks. Use
        :func:`verify_env_encrypt_public_key` with a timestamp from the KMS
        response whenever possible.
    """
    warnings.warn(
        "verify_env_encrypt_public_key_legacy is deprecated; use "
        "verify_env_encrypt_public_key with a timestamp from KMS instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    if len(signature) != 65:
        return None

    app_id_bytes = _normalize_app_id(app_id)
    if app_id_bytes is None:
        return None

    message = _PREFIX + _SEPARATOR + app_id_bytes + public_key
    return _recover_signer(keccak(message), signature)
