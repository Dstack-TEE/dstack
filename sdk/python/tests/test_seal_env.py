# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import base64
import json

from pyhpke import AEADId
from pyhpke import CipherSuite
from pyhpke import KDFId
from pyhpke import KEMId
import pytest

from dstack_sdk import EnvVar
from dstack_sdk import seal_env


@pytest.mark.parametrize("app_epoch", [0, 2])
def test_sealed_env_round_trip(app_epoch):
    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
    )
    keys = suite.kem.derive_key_pair(b"public sealed env test fixture")
    envelope = json.loads(
        seal_env(
            [EnvVar("MESSAGE", "Hello 世界")],
            keys.public_key.to_public_bytes().hex(),
            2,
            app_epoch,
        )
    )
    assert envelope["version"] == 1
    assert envelope["root_epoch"] == 2
    context = suite.create_recipient_context(
        base64.b64decode(envelope["enc"]),
        keys.private_key,
        info=f"dstack-sealed-env-v1:2:{app_epoch}".encode(),
    )
    plaintext = context.open(base64.b64decode(envelope["ciphertext"]))
    assert json.loads(plaintext) == {"env": [{"key": "MESSAGE", "value": "Hello 世界"}]}
    wrong_epoch = suite.create_recipient_context(
        base64.b64decode(envelope["enc"]),
        keys.private_key,
        info=f"dstack-sealed-env-v1:3:{app_epoch}".encode(),
    )
    with pytest.raises(Exception):
        wrong_epoch.open(base64.b64decode(envelope["ciphertext"]))


@pytest.mark.parametrize("epoch", [-1, 2**32, True, 0.5])
def test_invalid_sealed_epoch(epoch):
    with pytest.raises(ValueError, match="uint32"):
        seal_env([], "", epoch)


@pytest.mark.parametrize("app_epoch", [0, 2])
def test_sealed_key_signature_context(app_epoch):
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
        b"dstack-sealed-env-pubkey-v1:"
        + app
        + epoch.to_bytes(4, "big")
        + app_epoch.to_bytes(4, "big")
        + public_key
        + timestamp.to_bytes(8, "big")
    )
    signature = signer.sign_msg_hash(keccak(message)).to_bytes()
    trusted = "0x" + signer.public_key.to_compressed_bytes().hex()
    assert (
        verify_sealed_env_public_key(
            public_key, signature, app.hex(), epoch, timestamp, app_epoch=app_epoch
        )
        == trusted
    )
    assert (
        verify_sealed_env_public_key(
            public_key, signature, app.hex(), epoch + 1, timestamp, app_epoch=app_epoch
        )
        != trusted
    )
    assert (
        verify_sealed_env_public_key(
            public_key,
            signature,
            app.hex(),
            epoch,
            timestamp - 1000,
            app_epoch=app_epoch,
        )
        is None
    )

    assert (
        verify_sealed_env_public_key(
            public_key, signature, app.hex(), epoch, timestamp, app_epoch=app_epoch + 1
        )
        != trusted
    )
