# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Environment variable encryption module for dstack SDK.

Provides functionality to encrypt environment variables using X25519 key exchange
and AES-GCM encryption, similar to the TypeScript implementation.
"""

import json
import secrets
from typing import List
from typing import NamedTuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EnvVar(NamedTuple):
    """Environment variable key-value pair."""

    key: str
    value: str


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


async def encrypt_env_vars(envs: List[EnvVar], public_key_hex: str) -> str:
    """Encrypt environment variables using X25519 and AES-GCM.

    - Generate an ephemeral keypair and compute a shared secret with the remote
      public key
    - Encrypt the JSON payload with AES-GCM using the shared secret
    - Return concatenation of ephemeral public key + IV + ciphertext as hex
    """
    # Prepare environment data as JSON
    env_dict = {"env": [{"key": env.key, "value": env.value} for env in envs]}
    env_json = json.dumps(env_dict).encode("utf-8")

    # Generate private key and derive public key
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get public key bytes (32 bytes for X25519)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # Generate shared secret
    remote_public_key = X25519PublicKey.from_public_bytes(hex_to_bytes(public_key_hex))
    shared_secret = private_key.exchange(remote_public_key)

    # Encrypt the data using AES-GCM
    aesgcm = AESGCM(shared_secret)
    iv = secrets.token_bytes(12)  # 12 bytes IV for GCM
    encrypted_data = aesgcm.encrypt(iv, env_json, None)

    # Combine all components: public_key + iv + encrypted_data
    result = public_key_bytes + iv + encrypted_data

    return bytes_to_hex(result)


def encrypt_env_vars_sync(envs: List[EnvVar], public_key_hex: str) -> str:
    """Encrypt environment variables synchronously using X25519 and AES-GCM."""
    # Prepare environment data as JSON
    env_dict = {"env": [{"key": env.key, "value": env.value} for env in envs]}
    env_json = json.dumps(env_dict).encode("utf-8")

    # Generate private key and derive public key
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get public key bytes (32 bytes for X25519)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # Generate shared secret
    remote_public_key = X25519PublicKey.from_public_bytes(hex_to_bytes(public_key_hex))
    shared_secret = private_key.exchange(remote_public_key)

    # Encrypt the data using AES-GCM
    aesgcm = AESGCM(shared_secret)
    iv = secrets.token_bytes(12)  # 12 bytes IV for GCM
    encrypted_data = aesgcm.encrypt(iv, env_json, None)

    # Combine all components: public_key + iv + encrypted_data
    result = public_key_bytes + iv + encrypted_data

    return bytes_to_hex(result)
