# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Mint guest API tokens the way an application inside the CVM may."""

from __future__ import annotations

import base64
import json
import subprocess
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ISSUER_DOMAIN = "dstack:guest-api:issuer:v1"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


HEADER = _b64url(b'{"alg":"EdDSA","typ":"JWT"}')


def _post(socket: str, route: str, body: dict) -> dict:
    output = subprocess.run(
        ["curl", "--silent", "--fail", "--unix-socket", socket, "--request", "POST"]
        + ["--header", "Content-Type: application/json"]
        + ["--data-binary", json.dumps(body), f"http://localhost{route}"],
        capture_output=True,
        timeout=30,
        check=True,
    ).stdout
    return json.loads(output)


def mint(guest: dict, scopes: str, lifetime: int = 600) -> str:
    """Sign a token for `scopes` with the app's internal issuer key.

    `guest` is the fixture's internal DstackGuest service: any process that
    reaches it may derive the issuer key, so this is what an app can do.
    """
    socket, route = guest["socket"], guest["route"]
    key = _post(
        socket,
        route.replace("<Method>", "v1/GetKey"),
        {"domain": ISSUER_DOMAIN, "algorithm": "ed25519"},
    )["key"]
    app_id = _post(socket, route.replace("<Method>", "Info"), {})["app_id"]
    now = int(time.time())
    claims = {
        "iss": f"dstack:guest-api:{app_id}",
        "aud": app_id,
        "iat": now,
        "exp": now + lifetime,
        "scope": scopes,
    }
    signing_input = f"{HEADER}.{_b64url(json.dumps(claims).encode())}"
    signature = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key)).sign(
        signing_input.encode()
    )
    return f"{signing_input}.{_b64url(signature)}"
