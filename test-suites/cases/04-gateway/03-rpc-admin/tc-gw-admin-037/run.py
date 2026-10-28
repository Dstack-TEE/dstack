#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Exercise Admin.ImportCert on a case-owned three-node Gateway cluster."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CASE_ID = "tc-gw-admin-037"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def issue(domain: str, *, expired: bool = False) -> tuple[str, str, bytes]:
    """Return a self-signed wildcard certificate, its key, and the leaf DER."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before, not_after = (
        (now - datetime.timedelta(days=3), now - datetime.timedelta(days=1))
        if expired
        else (now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=2))
    )
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"*.{domain}")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(f"*.{domain}")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        key_pem,
        certificate.public_bytes(serialization.Encoding.DER),
    )


def varint(value: int) -> bytes:
    """Encode a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def protobuf_request(domain: str, cert_pem: str, key_pem: str) -> bytes:
    """Encode ImportCertRequest {domain=1, cert_pem=2, key_pem=3}."""
    output = bytearray()
    for number, value in ((1, domain), (2, cert_pem), (3, key_pem)):
        raw = value.encode()
        output.extend(varint((number << 3) | 2) + varint(len(raw)) + raw)
    return bytes(output)


def call(
    admin_url: str, token: str | None, body: bytes, content_type: str
) -> tuple[int, bytes]:
    """Call Admin.ImportCert and return its status and bounded body."""
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{admin_url.rstrip('/')}/Admin.ImportCert",
        data=body,
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status), response.read(65536)
    except urllib.error.HTTPError as error:
        return int(error.code), error.read(65536)
    except OSError:
        return 0, b""


def import_json(admin_url: str, token: str | None, value: dict[str, str]) -> int:
    """Import one JSON-encoded certificate."""
    return call(admin_url, token, json.dumps(value).encode(), "application/json")[0]


def served_leaf(proxy_address: str, server_name: str) -> bytes | None:
    """Return the DER leaf the proxy presents for one SNI, or None."""
    host, port = proxy_address.rsplit(":", 1)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as stream:
                return stream.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None


def all_serve(nodes: list[dict[str, Any]], server_name: str, leaf: bytes) -> bool:
    """Wait until every node presents one exact leaf for the SNI."""
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if all(
            served_leaf(str(node["proxy_address"]), server_name) == leaf
            for node in nodes
        ):
            return True
        time.sleep(0.25)
    return False


def main() -> int:
    """Run authorization, both representations, replication, and refusals."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise SystemExit(f"unsupported case: {os.environ['DSTACK_TEST_CASE_ID']}")
    started = time.monotonic()
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    cluster = manifest["values"]["gateway_cluster"]
    nodes = list(cluster["nodes"])
    token = pathlib.Path(cluster["admin_auth_token_file"]).read_text().strip()
    lease = str(manifest.get("lease_id", "lease"))[-10:].replace("-", "").lower()
    domain = f"import-{lease}.localhost"
    # `gateway.` is answered by the node itself, so the handshake completes
    # without a registered app behind the name.
    server_name = f"gateway.{domain}"
    adjacent_name = "gateway.localhost"
    primary = str(nodes[0]["admin_url"])
    secondary = str(nodes[1]["admin_url"])
    checks: dict[str, bool] = {}
    observation: dict[str, Any] = {"node_count": len(nodes)}
    steps: list[dict[str, str]] = []
    status = "FAIL"
    summary = "Admin.ImportCert matrix did not complete"

    def passed(number: int, observed: str) -> None:
        step_id = f"{CASE_ID}-step-{number:02d}"
        steps.append({"id": step_id, "status": "PASS", "observed": observed})
        print(f"EVIDENCE {step_id} - {observed}", flush=True)
        print(f"STEP {step_id} END - PASS", flush=True)

    try:
        print(f"STEP {CASE_ID}-step-01 START", flush=True)
        adjacent_leaves = [
            served_leaf(str(node["proxy_address"]), adjacent_name) for node in nodes
        ]
        checks["baseline_cluster"] = len(nodes) >= 3
        checks["baseline_domain_unserved"] = all(
            served_leaf(str(node["proxy_address"]), server_name) is None
            for node in nodes
        )
        checks["baseline_adjacent_served"] = all(adjacent_leaves)
        if not all(checks.values()):
            raise AssertionError(
                f"baseline failed: {sorted(k for k, v in checks.items() if not v)}"
            )
        passed(
            1,
            f"{len(nodes)} nodes served the fixture certificate and none served the run-scoped domain.",
        )

        print(f"STEP {CASE_ID}-step-02 START", flush=True)
        first_cert, first_key, first_leaf = issue(domain)
        second_cert, second_key, second_leaf = issue(domain)
        observation["unauthenticated_http"] = import_json(
            primary,
            None,
            {"domain": domain, "cert_pem": first_cert, "key_pem": first_key},
        )
        checks["unauthenticated_refused"] = observation["unauthenticated_http"] == 401
        checks["unauthenticated_not_served"] = (
            served_leaf(str(nodes[0]["proxy_address"]), server_name) is None
        )
        json_code, json_body = call(
            primary,
            token,
            json.dumps(
                {
                    "domain": f"*.{domain.upper()}.",
                    "cert_pem": first_cert,
                    "key_pem": first_key,
                }
            ).encode(),
            "application/json",
        )
        observation["json_http"] = json_code
        checks["json_import_accepted"] = json_code == 200 and json.loads(
            json_body or b"null"
        ) in (None, {})
        checks["json_import_normalized_and_replicated"] = all_serve(
            nodes, server_name, first_leaf
        )
        pb_code, _ = call(
            secondary,
            token,
            protobuf_request(domain, second_cert, second_key),
            "application/octet-stream",
        )
        observation["protobuf_http"] = pb_code
        checks["protobuf_import_accepted"] = pb_code == 200
        checks["protobuf_import_replaces_and_replicates"] = all_serve(
            nodes, server_name, second_leaf
        )
        checks["adjacent_domain_unchanged"] = [
            served_leaf(str(node["proxy_address"]), adjacent_name) for node in nodes
        ] == adjacent_leaves
        if not all(checks.values()):
            raise AssertionError(
                f"import checks failed: {sorted(k for k, v in checks.items() if not v)}; {observation}"
            )
        passed(
            2,
            "JSON and protobuf imports were accepted with a bearer token, the wildcard, case and trailing-dot spelling normalized, and every node served the latest import while the adjacent domain kept its certificate.",
        )

        print(f"STEP {CASE_ID}-step-03 START", flush=True)
        expired_cert, expired_key, _ = issue(domain, expired=True)
        _, third_key, _ = issue(domain)
        refusals = {
            "empty_domain": {
                "domain": "",
                "cert_pem": first_cert,
                "key_pem": first_key,
            },
            "malformed_domain": {
                "domain": f"bad..{domain}",
                "cert_pem": first_cert,
                "key_pem": first_key,
            },
            "unparsable_certificate": {
                "domain": domain,
                "cert_pem": "not a certificate",
                "key_pem": first_key,
            },
            "expired_certificate": {
                "domain": domain,
                "cert_pem": expired_cert,
                "key_pem": expired_key,
            },
            "mismatched_key": {
                "domain": domain,
                "cert_pem": first_cert,
                "key_pem": third_key,
            },
        }
        refusal_codes = {
            name: import_json(primary, token, value) for name, value in refusals.items()
        }
        observation["refusal_http"] = refusal_codes
        checks["invalid_imports_refused"] = all(
            400 <= code < 500 for code in refusal_codes.values()
        )
        checks["refusals_keep_previous_certificate"] = all_serve(
            nodes, server_name, second_leaf
        )
        checks["listener_still_answers"] = (
            import_json(
                primary,
                token,
                {"domain": domain, "cert_pem": second_cert, "key_pem": second_key},
            )
            == 200
        )
        if not all(checks.values()):
            raise AssertionError(
                f"refusal checks failed: {sorted(k for k, v in checks.items() if not v)}; {refusal_codes}"
            )
        passed(
            3,
            "Empty and malformed domains, an unparsable or expired certificate, and a mismatched key were refused with 4xx while every node kept serving the previous import.",
        )
        status = "PASS"
        summary = "Admin.ImportCert authorization, representations, normalization, replication, refusals and isolation passed."
    except Exception as error:  # noqa: BLE001
        summary = f"Admin.ImportCert matrix failed: {error}"
        failed = len(steps) + 1
        for number in range(failed, 4):
            steps.append(
                {
                    "id": f"{CASE_ID}-step-{number:02d}",
                    "status": "FAIL" if number == failed else "NOT_RUN",
                    "observed": summary
                    if number == failed
                    else "Not run after failure.",
                }
            )
    observation["checks"] = checks
    artifact = {
        "path": "artifacts/gateway-import-cert.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Admin.ImportCert matrix",
        "description": "HTTP statuses, counts and booleans only; no certificate, key, token, URL or domain is retained.",
    }
    detail = result_dir / artifact["path"]
    atomic_json(detail, observation)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": [artifact],
            "evidence": [
                {
                    "path": artifact["path"],
                    "sha256": hashlib.sha256(detail.read_bytes()).hexdigest(),
                }
            ],
            "remarks": "The imported certificates are case-generated and stay in the lease-owned cluster store, which is discarded with the lease; Admin has no delete for an imported certificate.",
            "duration_seconds": round(time.monotonic() - started, 3),
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
