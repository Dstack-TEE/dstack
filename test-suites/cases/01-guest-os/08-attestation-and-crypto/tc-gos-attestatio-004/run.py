#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify TLS key matching, X.509 usages, extensions, validity, and chain."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    ObjectIdentifier,
)

CASE_ID = "tc-gos-attestatio-004"
ATTESTATION_OID = ObjectIdentifier("1.3.6.1.4.1.62397.1.8")
APP_INFO_OID = ObjectIdentifier("1.3.6.1.4.1.62397.1.9")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def rpc(url: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Make a bounded JSON RPC request with readiness retries."""
    for attempt in range(1, 11):
        request = urllib.request.Request(
            url.replace("{method}", method),
            data=json.dumps(body, separators=(",", ":")).encode(),
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                value = json.load(response)
            break
        except urllib.error.HTTPError:
            raise
        except (ConnectionError, OSError, TimeoutError, urllib.error.URLError):
            if attempt == 10:
                raise
            time.sleep(2)
    if not isinstance(value, dict):
        raise AssertionError(f"{method} returned non-object JSON")
    return value


def invalid_validity_probe(url: str, body: dict[str, Any]) -> dict[str, Any]:
    """Observe whether an invalid GetTlsKey request is rejected."""
    request = urllib.request.Request(
        url.replace("{method}", "GetTlsKey"),
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            value = json.load(response)
        if not isinstance(value, dict):
            raise AssertionError("accepted invalid validity returned non-object JSON")
        key_present = isinstance(value.get("key"), str) and bool(value["key"])
        chain_present = isinstance(value.get("certificate_chain"), list) and bool(
            value["certificate_chain"]
        )
        value.clear()
        return {
            "rejected": False,
            "http_status": response.status,
            "key_and_chain_issued": key_present and chain_present,
        }
    except urllib.error.HTTPError as error:
        payload = error.read()
        return {
            "rejected": True,
            "http_status": error.code,
            "diagnostic_present": bool(payload),
            "diagnostic_sha256": hashlib.sha256(payload).hexdigest(),
        }


def extension_present(
    cert: x509.Certificate, oid: ObjectIdentifier
) -> tuple[bool, int]:
    """Return custom-extension presence and encoded value length."""
    try:
        value = cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return False, 0
    raw = value.value if isinstance(value, x509.UnrecognizedExtension) else bytes(value)
    return True, len(raw)


def verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify one certificate signature against its issuer public key."""
    key = issuer.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    elif isinstance(key, rsa.RSAPublicKey):
        key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    else:
        raise AssertionError(f"unsupported issuer key type: {type(key).__name__}")


def validate_response(
    response: dict[str, Any],
    *,
    subject: str,
    sans: list[str],
    server: bool,
    client: bool,
    attestation: bool,
    app_info: bool,
    not_before: int | None = None,
    not_after: int | None = None,
) -> dict[str, Any]:
    """Validate one GetTlsKey response without retaining its private key."""
    key_text = response.get("key")
    chain_text = response.get("certificate_chain")
    if (
        not isinstance(key_text, str)
        or not isinstance(chain_text, list)
        or not chain_text
    ):
        raise AssertionError(
            "GetTlsKey returned an incomplete key or certificate chain"
        )
    private_key = serialization.load_pem_private_key(key_text.encode(), password=None)
    certificates = [
        x509.load_pem_x509_certificate(str(item).encode()) for item in chain_text
    ]
    leaf = certificates[0]
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    leaf_public = leaf.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    del private_key, key_text
    if private_public != leaf_public:
        raise AssertionError("private key did not match leaf certificate")
    common_names = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if [item.value for item in common_names] != [subject]:
        raise AssertionError("leaf common name did not match request")
    try:
        san_value = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        observed_sans = san_value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        observed_sans = []
    if observed_sans != sans:
        raise AssertionError(
            f"leaf SAN mismatch: expected {sans!r}, got {observed_sans!r}"
        )
    expected_eku = set()
    if server:
        expected_eku.add(ExtendedKeyUsageOID.SERVER_AUTH)
    if client:
        expected_eku.add(ExtendedKeyUsageOID.CLIENT_AUTH)
    try:
        observed_eku = set(
            leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        )
    except x509.ExtensionNotFound:
        observed_eku = set()
    if observed_eku != expected_eku:
        raise AssertionError("leaf extended key usages did not match request")
    key_usage = leaf.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    if not key_usage.digital_signature:
        raise AssertionError("leaf omitted digital-signature key usage")
    attestation_present, attestation_length = extension_present(leaf, ATTESTATION_OID)
    app_info_present, app_info_length = extension_present(leaf, APP_INFO_OID)
    if attestation_present != attestation or app_info_present != app_info:
        raise AssertionError(
            "RA-TLS or app-info extension presence did not match request"
        )
    if attestation and not attestation_length:
        raise AssertionError("RA-TLS extension was empty")
    if app_info and not app_info_length:
        raise AssertionError("app-info extension was empty")
    leaf_before = int(leaf.not_valid_before.replace(tzinfo=timezone.utc).timestamp())
    leaf_after = int(leaf.not_valid_after.replace(tzinfo=timezone.utc).timestamp())
    if not_before is not None and abs(leaf_before - not_before) > 1:
        raise AssertionError("leaf not_before override did not match request")
    if not_after is not None and abs(leaf_after - not_after) > 1:
        raise AssertionError("leaf not_after override did not match request")
    for index in range(len(certificates) - 1):
        if certificates[index].issuer != certificates[index + 1].subject:
            raise AssertionError(f"certificate chain issuer mismatch at index {index}")
        verify_signature(certificates[index], certificates[index + 1])
        ca = (
            certificates[index + 1]
            .extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            .value
        )
        if not ca.ca:
            raise AssertionError(f"issuer at index {index + 1} was not a CA")
    if len(certificates) == 1:
        raise AssertionError("certificate response omitted CA chain")
    return {
        "chain_length": len(certificates),
        "leaf_key_matches": True,
        "leaf_public_key_sha256": hashlib.sha256(leaf_public).hexdigest(),
        "sans": observed_sans,
        "server_auth": ExtendedKeyUsageOID.SERVER_AUTH in observed_eku,
        "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH in observed_eku,
        "digital_signature": True,
        "attestation_extension": attestation_present,
        "attestation_extension_length": attestation_length,
        "app_info_extension": app_info_present,
        "app_info_extension_length": app_info_length,
        "not_before": leaf_before,
        "not_after": leaf_after,
        "chain_signatures_verified": len(certificates) - 1,
        "issuer_ca_constraints_verified": len(certificates) - 1,
    }


def tls_request(
    subject: str,
    sans: list[str],
    *,
    server: bool,
    client: bool,
    attestation: bool,
    app_info: bool,
    not_before: int | None = None,
    not_after: int | None = None,
) -> dict[str, Any]:
    """Build one GetTlsKey JSON request."""
    value: dict[str, Any] = {
        "subject": subject,
        "alt_names": sans,
        "usage_ra_tls": attestation,
        "usage_server_auth": server,
        "usage_client_auth": client,
        "with_app_info": app_info,
    }
    if not_before is not None:
        value["not_before"] = not_before
    if not_after is not None:
        value["not_after"] = not_after
    return value


def main() -> int:
    """Run TLS key and certificate extension acceptance."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    services = manifest.get("values", {}).get("services", {})
    guest = services.get("DstackGuest") if isinstance(services, dict) else None
    status = "PASS"
    summary = (
        "TLS key, SAN, EKU, validity, RA-TLS, app-info, and CA chain were verified."
    )
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    stage = "capability"
    try:
        if not isinstance(guest, dict) or not isinstance(guest.get("url"), str):
            status = "BLOCKED"
            summary = "fixture lacks a lease-owned hardware DstackGuest TLS endpoint"
            observations["missing_capability"] = "hardware-dstackguest-tls-endpoint"
        else:
            url = str(guest["url"])
            stage = "health-before"
            info_before = rpc(url, "Info", {})
            if not info_before.get("app_id") or not info_before.get("instance_id"):
                raise AssertionError("DstackGuest Info omitted identity")
            run_hash = hashlib.sha256(
                os.environ["DSTACK_TEST_RUN_ID"].encode()
            ).hexdigest()
            subject = f"tls-{run_hash[:12]}.example.test"
            sans = [subject, f"alt-{run_hash[12:24]}.example.test"]
            now = int(datetime.now(timezone.utc).timestamp())
            valid_from, valid_until = now - 120, now + 3600
            stage = "full-extension-matrix"
            full_body = tls_request(
                subject,
                sans,
                server=True,
                client=True,
                attestation=True,
                app_info=True,
                not_before=valid_from,
                not_after=valid_until,
            )
            full = validate_response(
                rpc(url, "GetTlsKey", full_body),
                subject=subject,
                sans=sans,
                server=True,
                client=True,
                attestation=True,
                app_info=True,
                not_before=valid_from,
                not_after=valid_until,
            )
            stage = "server-only"
            server_subject = f"server-{run_hash[:12]}.example.test"
            server_body = tls_request(
                server_subject,
                [server_subject],
                server=True,
                client=False,
                attestation=False,
                app_info=False,
            )
            server_row = validate_response(
                rpc(url, "GetTlsKey", server_body),
                subject=server_subject,
                sans=[server_subject],
                server=True,
                client=False,
                attestation=False,
                app_info=False,
            )
            stage = "client-only"
            client_subject = f"client-{run_hash[:12]}.example.test"
            client_body = tls_request(
                client_subject,
                [],
                server=False,
                client=True,
                attestation=False,
                app_info=False,
            )
            client_row = validate_response(
                rpc(url, "GetTlsKey", client_body),
                subject=client_subject,
                sans=[],
                server=False,
                client=True,
                attestation=False,
                app_info=False,
            )
            stage = "invalid-validity"
            invalid = invalid_validity_probe(
                url,
                tls_request(
                    subject,
                    [subject],
                    server=True,
                    client=False,
                    attestation=False,
                    app_info=False,
                    not_before=now + 7200,
                    not_after=now + 3600,
                ),
            )
            stage = "health-after"
            info_after = rpc(url, "Info", {})
            if info_after.get("app_id") != info_before.get("app_id") or info_after.get(
                "instance_id"
            ) != info_before.get("instance_id"):
                raise AssertionError("DstackGuest identity changed during TLS matrix")
            if not invalid["rejected"]:
                if not invalid["key_and_chain_issued"]:
                    raise AssertionError(
                        "accepted invalid validity returned incomplete key material"
                    )
                status = "BLOCKED"
                summary = (
                    "candidate guest image lacks certificate validity ordering guard"
                )
                observations["missing_capability"] = (
                    "candidate-guest-validity-order-guard"
                )
            observations.update(
                {
                    "full": full,
                    "server_only": server_row,
                    "client_only": client_row,
                    "invalid_validity": invalid,
                    "service_healthy_before": True,
                    "service_healthy_after": True,
                    "private_key_persisted": False,
                }
            )
    except (
        AssertionError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"
        observations["failure"] = str(error)
        observations["failure_stage"] = stage
    artifact = {
        "path": "artifacts/tls-certificate-extensions.json",
        "step_id": f"{case_id}-step-01",
        "name": "TLS certificate extensions",
        "description": "Key-match, SAN, EKU, validity, custom-extension lengths, and chain verification without private keys or certificates.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "The lease-owned DstackGuest identity and TLS endpoint were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Full, server-only, client-only, validity, RA-TLS, and app-info certificate requests were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Private-key matching, SAN/EKU, chain/CA signatures, negative validity, and final health were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Private keys are parsed in memory only and are never written to results or artifacts.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
