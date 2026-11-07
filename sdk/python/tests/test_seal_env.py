# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import base64
import json

import pytest
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from dstack_sdk import EnvVar, seal_env


def test_sealed_env_round_trip():
    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
    )
    keys = suite.kem.derive_key_pair(b"public sealed env test fixture")
    envelope = json.loads(seal_env(
        [EnvVar("MESSAGE", "Hello 世界")], keys.public_key.to_public_bytes().hex(), 2
    ))
    assert envelope["version"] == 1
    assert envelope["root_epoch"] == 2
    context = suite.create_recipient_context(
        base64.b64decode(envelope["enc"]), keys.private_key,
        info=b"dstack-sealed-env-v1:2",
    )
    plaintext = context.open(base64.b64decode(envelope["ciphertext"]))
    assert json.loads(plaintext) == {"env": [{"key": "MESSAGE", "value": "Hello 世界"}]}
    wrong_epoch = suite.create_recipient_context(
        base64.b64decode(envelope["enc"]), keys.private_key,
        info=b"dstack-sealed-env-v1:3",
    )
    with pytest.raises(Exception):
        wrong_epoch.open(base64.b64decode(envelope["ciphertext"]))


@pytest.mark.parametrize("epoch", [-1, 2**32, True, 0.5])
def test_invalid_sealed_epoch(epoch):
    with pytest.raises(ValueError, match="uint32"):
        seal_env([], "", epoch)


def test_sealed_key_signature_context():
    import time
    from eth_keys import keys
    from eth_utils import keccak
    from dstack_sdk import verify_sealed_env_public_key

    signer = keys.PrivateKey(bytes([7]) * 32)
    app = bytes([1]) * 20
    public_key = bytes([2]) * 32
    epoch = 3
    timestamp = int(time.time())
    message = (
        b"dstack-sealed-env-pubkey-v1:" + app + epoch.to_bytes(4, "big")
        + public_key + timestamp.to_bytes(8, "big")
    )
    signature = signer.sign_msg_hash(keccak(message)).to_bytes()
    trusted = "0x" + signer.public_key.to_compressed_bytes().hex()
    assert verify_sealed_env_public_key(public_key, signature, app.hex(), epoch, timestamp) == trusted
    assert verify_sealed_env_public_key(public_key, signature, app.hex(), epoch + 1, timestamp) != trusted
    assert verify_sealed_env_public_key(public_key, signature, app.hex(), epoch, timestamp - 1000) is None
