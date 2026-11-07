# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""HPKE encryption for the versioned .sealed-env envelope."""

import base64
import json
from typing import List

from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from .encrypt_env_vars import EnvVar


def seal_env(envs: List[EnvVar], public_key_hex: str, root_epoch: int) -> str:
    """Seal envs to a trusted epoch public key and return the JSON envelope."""
    if isinstance(root_epoch, bool) or not isinstance(root_epoch, int) or not 0 <= root_epoch <= 0xFFFFFFFF:
        raise ValueError("root_epoch must be a uint32")
    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
    )
    public_key = suite.kem.deserialize_public_key(bytes.fromhex(public_key_hex.removeprefix("0x")))
    plaintext = json.dumps({"env": [{"key": env.key, "value": env.value} for env in envs]}).encode()
    enc, context = suite.create_sender_context(
        public_key, info=f"dstack-sealed-env-v1:{root_epoch}".encode()
    )
    ciphertext = context.seal(plaintext)
    return json.dumps({
        "version": 1,
        "root_epoch": root_epoch,
        "enc": base64.b64encode(enc).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    })
