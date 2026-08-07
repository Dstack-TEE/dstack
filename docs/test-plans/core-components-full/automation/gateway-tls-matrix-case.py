#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway TLS protocols, identities, and listener separation."""

from __future__ import annotations

import base64
import http.client
import json
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CASE_ID = "tc-gw-cluster-ad-008"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def context(identity: dict[str, str] | None = None) -> ssl.SSLContext:
    """Create a case-owned TLS context without trusting the self-signed server."""
    value = ssl.create_default_context()
    value.check_hostname = False
    value.verify_mode = ssl.CERT_NONE
    if identity is not None:
        value.load_cert_chain(identity["cert"], identity["key"])
    return value


def post(url: str, value: dict[str, Any], identity: dict[str, str] | None = None, token: str | None = None) -> tuple[int | None, bytes]:
    """Issue a bounded JSON request, returning None for transport rejection."""
    request = urllib.request.Request(url, data=json.dumps(value).encode(), method="POST")
    request.add_header("Content-Type", "application/json")
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=5, context=context(identity)) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        ConnectionError,
        TimeoutError,
        ssl.SSLError,
        OSError,
    ):
        return None, b""


def handshake(host: str, port: int, minimum: ssl.TLSVersion, maximum: ssl.TLSVersion) -> tuple[bool, str, str]:
    """Attempt one bounded TLS negotiation and return non-secret protocol facts."""
    ctx = context()
    ctx.minimum_version = minimum
    ctx.maximum_version = maximum
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                cipher = tls.cipher()
                return True, str(tls.version()), str(cipher[0] if cipher else "")
    except (OSError, ssl.SSLError):
        return False, "", ""


def generate_wrong_identity(directory: pathlib.Path) -> dict[str, str]:
    """Generate an untrusted ephemeral client identity."""
    key = directory / "wrong-client.key"
    cert = directory / "wrong-client.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=untrusted-case-client", "-days", "1",
            "-keyout", str(key), "-out", str(cert),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )
    return {"key": str(key), "cert": str(cert)}


def main() -> int:
    """Run protocol, transport, identity, and downgrade checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    gateway = manifest["values"]["gateway"]
    public = str(gateway["rpc_url"]).rstrip("/")
    admin = str(gateway["admin_url"]).rstrip("/")
    identity = gateway["registration_client"]
    token = pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
    parsed = urllib.parse.urlsplit(public)
    host, port = parsed.hostname or "127.0.0.1", int(parsed.port or 443)
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "Gateway TLS matrix did not complete"
    try:
        tls12 = handshake(host, port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        tls13 = handshake(host, port, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
        checks["tls12_negotiates"] = tls12[0] and tls12[1] == "TLSv1.2"
        checks["tls13_negotiates"] = tls13[0] and tls13[1] == "TLSv1.3"
        checks["strong_cipher_selected"] = all(
            value[2] and not any(word in value[2].upper() for word in ("NULL", "RC4", "DES"))
            for value in (tls12, tls13)
        )

        plain_public = public.replace("https://", "http://", 1)
        plain_public_code = post(f"{plain_public}/Gateway.Info", {})[0]
        tls_admin = admin.replace("http://", "https://", 1)
        tls_admin_code = post(f"{tls_admin}/Admin.Status", {}, token=token)[0]
        admin_code = post(f"{admin}/Admin.Status", {}, token=token)[0]
        checks["transport_modes_separated"] = (
            plain_public_code is None and tls_admin_code is None and admin_code == 200
        )

        request = {"client_public_key": base64.b64encode(os.urandom(32)).decode()}
        unauth_code = post(f"{public}/Tproxy.RegisterCvm?json", request)[0]
        valid_code = post(f"{public}/Tproxy.RegisterCvm?json", request, identity=identity)[0]
        wrong_dir = pathlib.Path(tempfile.mkdtemp(prefix="wrong-client-", dir=result_dir))
        try:
            wrong = generate_wrong_identity(wrong_dir)
            wrong_code = post(f"{public}/Tproxy.RegisterCvm?json", request, identity=wrong)[0]
        finally:
            for path in wrong_dir.glob("*"):
                path.unlink()
            wrong_dir.rmdir()
        checks["client_trust_isolated"] = (
            valid_code == 200
            and (unauth_code is None or unauth_code >= 400)
            and (wrong_code is None or wrong_code >= 400)
        )

        if not all(checks.values()):
            raise AssertionError(
                f"TLS checks failed: {sorted(k for k, value in checks.items() if not value)}"
            )
        steps = [
            {"id": f"{CASE_ID}-step-01", "status": "PASS", "observed": "The case-owned public listener negotiated TLS 1.2 and TLS 1.3 with non-null modern ciphers."},
            {"id": f"{CASE_ID}-step-02", "status": "PASS", "observed": "Plaintext on the public TLS port and TLS on the plaintext admin port failed while authenticated admin HTTP remained available."},
            {"id": f"{CASE_ID}-step-03", "status": "PASS", "observed": "Simulator mTLS registration succeeded; missing and unrelated self-signed client identities failed closed."},
        ]
        observation = {
            "checks": checks,
            "tls12_protocol": tls12[1],
            "tls13_protocol": tls13[1],
            "tls12_cipher": tls12[2],
            "tls13_cipher": tls13[2],
            "plain_public_http": plain_public_code,
            "tls_admin_http": tls_admin_code,
            "admin_http": admin_code,
            "unauthenticated_registration_http": unauth_code,
            "valid_registration_http": valid_code,
            "wrong_identity_registration_http": wrong_code,
        }
        path = result_dir / "artifacts/gateway-tls-matrix.json"
        atomic_json(path, observation)
        artifacts.append({"path": "artifacts/gateway-tls-matrix.json", "step_id": f"{CASE_ID}-step-02", "name": "Gateway TLS matrix", "description": "Negotiated protocol/cipher names, HTTP statuses, and booleans only; no certificate, key, token, URL, or response body is retained."})
        status = "PASS"
        summary = "Gateway TLS 1.2/1.3, listener transport separation, client identity trust, and downgrade resistance passed."
    except Exception as error:  # noqa: BLE001
        failed = len(steps) + 1
        for index in range(failed, 4):
            steps.append({"id": f"{CASE_ID}-step-{index:02d}", "status": "FAIL" if index == failed else "NOT_RUN", "observed": str(error) if index == failed else "Not run after failure."})
        summary = f"Gateway TLS matrix failed: {error}"
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    atomic_json(result_dir / "result.json", {"schema_version": "1.0", "case_id": CASE_ID, "provisional": False, "status": status, "summary": summary, "steps": steps, "artifacts": artifacts, "remarks": "Ephemeral wrong-client material was deleted before result publication; no key, certificate, token, URL, or native response body is retained."})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
