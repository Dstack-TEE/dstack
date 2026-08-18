#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify temporary-CA roles and persistence across a case-owned KMS restart."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

CASE_ID = "tc-kms-keys-certs-005"


def call(url: str, identity: dict[str, str]) -> tuple[int, bytes]:
    """Call GetTempCaCert with the lease-owned attested client."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(identity["cert"], identity["key"])
    request = urllib.request.Request(
        f"{url}/KMS.GetTempCaCert?json",
        data=b"{}",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def openssl(args: list[str]) -> bytes:
    """Run one bounded OpenSSL verification command."""
    completed = subprocess.run(
        ["openssl", *args], capture_output=True, check=False, timeout=20
    )
    if completed.returncode:
        raise AssertionError(completed.stderr.decode(errors="replace")[-500:])
    return completed.stdout


def replace_with_expiring_ca(cert: Path, key: Path, subject: str, pathlen: int) -> None:
    """Replace a lease-owned public CA certificate without exposing its key."""
    openssl(
        [
            "req",
            "-x509",
            "-new",
            "-key",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            f"/O=Dstack/CN={subject}",
            "-addext",
            f"basicConstraints=critical,CA:TRUE,pathlen:{pathlen}",
            "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
        ]
    )


def validate(payload: dict[str, str]) -> dict[str, object]:
    """Validate public certificate roles without retaining private material."""
    required = ("temp_ca_cert", "temp_ca_key", "ca_cert")
    if any(
        not isinstance(payload.get(key), str) or not payload[key] for key in required
    ):
        raise AssertionError("GetTempCaCert omitted required PEM fields")
    with tempfile.TemporaryDirectory(prefix="dstack-kms-temp-ca-") as directory:
        root = Path(directory)
        cert = root / "temp.crt"
        key = root / "temp.key"
        ca = root / "root.crt"
        cert.write_text(payload["temp_ca_cert"])
        key.write_text(payload["temp_ca_key"])
        ca.write_text(payload["ca_cert"])
        key.chmod(0o600)
        cert_pub = openssl(["x509", "-in", str(cert), "-pubkey", "-noout"])
        key_pub = openssl(["pkey", "-in", str(key), "-pubout"])
        root_pub = openssl(["x509", "-in", str(ca), "-pubkey", "-noout"])
        if cert_pub != key_pub:
            raise AssertionError("temporary CA certificate and key do not match")
        openssl(["verify", "-CAfile", str(cert), str(cert)])
        subject = openssl(["x509", "-in", str(cert), "-noout", "-subject"]).strip()
        issuer = openssl(["x509", "-in", str(cert), "-noout", "-issuer"]).strip()
        if subject.removeprefix(b"subject=") != issuer.removeprefix(b"issuer="):
            raise AssertionError("temporary CA is not self-signed")
        if (
            hashlib.sha256(cert.read_bytes()).digest()
            == hashlib.sha256(ca.read_bytes()).digest()
        ):
            raise AssertionError("temporary and root CA certificates are identical")
    return {
        "temp_cert_sha256": hashlib.sha256(
            payload["temp_ca_cert"].encode()
        ).hexdigest(),
        "temp_key_public_sha256": hashlib.sha256(key_pub).hexdigest(),
        "root_cert_sha256": hashlib.sha256(payload["ca_cert"].encode()).hexdigest(),
        "root_public_sha256": hashlib.sha256(root_pub).hexdigest(),
        "private_material_persisted": False,
    }


def wait_ready(
    url: str, identity: dict[str, str], timeout: float = 30
) -> dict[str, str]:
    """Wait for KMS and return its decoded response."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            code, raw = call(url, identity)
            if code == 200:
                return json.loads(raw)
        except (OSError, ValueError):
            pass
        time.sleep(0.2)
    raise TimeoutError("restarted KMS did not become ready")


def main() -> int:
    """Execute role, repeat, restart, and cleanup rows."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    case = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    values = case.get("values") or {}
    kms = values["kms"]
    identity = values["kms_attested_client"]
    replacement: subprocess.Popen[bytes] | None = None
    status = "FAIL"
    failure = ""
    rows: list[dict[str, object]] = []
    try:
        url = str(kms["rpc_prpc_url"])
        first = wait_ready(url, identity)
        first_shape = validate(first)
        second = wait_ready(url, identity)
        rows.append({"name": "credential_roles", "status": "PASS", **first_shape})
        if first != second:
            raise AssertionError("temporary CA response changed before restart")
        rows.append({"name": "repeat_stability", "status": "PASS"})

        old_pid = int(kms["pid"])
        os.kill(old_pid, signal.SIGTERM)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and Path(f"/proc/{old_pid}").exists():
            time.sleep(0.1)
        if Path(f"/proc/{old_pid}").exists():
            raise TimeoutError("original lease-owned KMS did not stop")
        binary = str(runtime["prepared_binaries"]["dstack_kms"]["path"])
        agent_socket = values["kms_guest_simulator"]["services"]["DstackGuest"][
            "socket"
        ]
        log = (artifacts / "replacement-kms.log").open("wb")
        replacement = subprocess.Popen(
            [binary, "--config", str(kms["config"])],
            env={**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{agent_socket}"},
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        after = wait_ready(url, identity)
        after_shape = validate(after)
        if first != after:
            raise AssertionError("temporary/root CA material changed after restart")
        rows.append({"name": "restart_persistence", "status": "PASS", **after_shape})

        os.killpg(replacement.pid, signal.SIGTERM)
        replacement.wait(timeout=10)
        replacement = None
        cert_dir = Path(kms["cert_dir"])
        replace_with_expiring_ca(
            cert_dir / "root-ca.crt",
            cert_dir / "root-ca.key",
            "Dstack KMS CA",
            1,
        )
        replace_with_expiring_ca(
            cert_dir / "tmp-ca.crt",
            cert_dir / "tmp-ca.key",
            "Dstack Client Temp CA",
            0,
        )
        replacement = subprocess.Popen(
            [binary, "--config", str(kms["config"])],
            env={**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{agent_socket}"},
            stdout=(artifacts / "renewal-kms.log").open("wb"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        renewed = wait_ready(url, identity)
        renewed_shape = validate(renewed)
        if renewed_shape["temp_cert_sha256"] == first_shape["temp_cert_sha256"]:
            raise AssertionError("temporary CA certificate was not renewed")
        if renewed_shape["root_cert_sha256"] == first_shape["root_cert_sha256"]:
            raise AssertionError("root CA certificate was not renewed")
        if (
            renewed_shape["temp_key_public_sha256"]
            != first_shape["temp_key_public_sha256"]
        ):
            raise AssertionError("temporary CA key changed during renewal")
        if renewed_shape["root_public_sha256"] != first_shape["root_public_sha256"]:
            raise AssertionError("root CA key changed during renewal")
        rows.append({"name": "near_expiry_renewal", "status": "PASS", **renewed_shape})
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        rows.append({"name": "failure", "status": "FAIL", "diagnostic": failure})
    finally:
        if replacement is not None and replacement.poll() is None:
            os.killpg(replacement.pid, signal.SIGTERM)
            try:
                replacement.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(replacement.pid, signal.SIGKILL)
                replacement.wait(timeout=5)

    evidence_path = artifacts / "kms-temp-ca-lifecycle.json"
    evidence_path.write_text(json.dumps({"rows": rows}, indent=2) + "\n")
    artifact = {
        "path": "artifacts/kms-temp-ca-lifecycle.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Temporary CA lifecycle matrix",
        "description": "Sanitized certificate-role, stability, restart, and cleanup evidence.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = "4/4 CA lifecycle rows passed" if status == "PASS" else failure
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "remarks": "Private key bodies were held only in memory and a deleted temporary directory.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
