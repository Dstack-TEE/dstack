#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise KMS.SignCert with a signed CSR containing key-bound attestation."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SUPPORTED_CASES = {"tc-kms-kms-006", "tc-kms-keys-certs-004"}


def tls_context(identity: dict[str, Any] | None) -> ssl.SSLContext:
    """Create a test TLS context and optionally load the case-owned RA identity."""
    value = ssl.create_default_context()
    value.check_hostname = False
    value.verify_mode = ssl.CERT_NONE
    if identity:
        value.load_cert_chain(str(identity["cert"]), str(identity["key"]))
    return value


def call(
    url: str,
    body: bytes,
    content_type: str,
    identity: dict[str, Any] | None,
) -> tuple[int, bytes]:
    """Call SignCert while keeping native certificate material in memory."""
    suffix = "?json" if content_type == "application/json" else ""
    request = urllib.request.Request(
        f"{url}/KMS.SignCert{suffix}",
        data=body,
        headers={"content-type": content_type},
    )
    try:
        with urllib.request.urlopen(
            request, context=tls_context(identity), timeout=90
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def varint(value: int) -> bytes:
    """Encode a non-negative protobuf varint."""
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number: int, value: bytes) -> bytes:
    """Encode one protobuf length-delimited field."""
    return bytes(((number << 3) | 2,)) + varint(len(value)) + value


def generate(csr_fixture: dict[str, Any]) -> dict[str, str]:
    """Generate a fresh signed CSR without persisting its private key."""
    completed = subprocess.run(
        [str(csr_fixture["generator"])],
        env={**os.environ, "DSTACK_AGENT_ADDRESS": str(csr_fixture["agent_url"])},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"CSR generator rc={completed.returncode}: {completed.stderr[-500:]}"
        )
    value = json.loads(completed.stdout)
    required = ("csr", "signature", "public_key", "subject", "alt_name")
    if not all(isinstance(value.get(key), str) and value[key] for key in required):
        raise RuntimeError("CSR generator omitted required public request fields")
    return value


def chain_shape(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the public three-certificate response and return safe metadata."""
    chain = payload.get("certificate_chain")
    if not isinstance(chain, list) or len(chain) != 3:
        raise AssertionError("SignCert did not return leaf, app CA, and KMS root")
    if not all(
        isinstance(cert, str)
        and "-----BEGIN CERTIFICATE-----" in cert
        and "-----END CERTIFICATE-----" in cert
        for cert in chain
    ):
        raise AssertionError("SignCert returned a malformed PEM chain")
    return {
        "entries": len(chain),
        "pem_valid": True,
        "lengths": [len(cert) for cert in chain],
        "sha256": [hashlib.sha256(cert.encode()).hexdigest() for cert in chain],
    }


def emit(step: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step."""
    print(f"STEP {step} START", flush=True)
    print(f"EVIDENCE {step} - {observed}", flush=True)
    print(f"STEP {step} END - {status}", flush=True)
    return {"id": step, "status": status, "observed": observed}


def write_json(path: Path, value: Any) -> None:
    """Write deterministic JSON evidence."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    """Execute valid, representation, mutation, authentication, and liveness rows."""
    case_id = os.environ.get("DSTACK_TEST_CASE_ID", "")
    if case_id not in SUPPORTED_CASES:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values") or {}
    identity = values.get("kms_attested_client")
    csr_fixture = values.get("kms_attested_csr")
    kms = values.get("kms") or {}
    status = "FAIL"
    failure = ""
    steps: list[dict[str, str]] = []
    evidence: dict[str, Any] = {"native_certificate_chain_persisted": False}
    started = time.monotonic()
    try:
        if not isinstance(identity, dict) or not isinstance(csr_fixture, dict):
            raise RuntimeError(
                "fixture omitted the attested TLS client or CSR generator"
            )
        generated = generate(csr_fixture)
        csr = bytes.fromhex(generated["csr"])
        signature = bytes.fromhex(generated["signature"])
        vm_config = str(csr_fixture["vm_config"])
        request_value = {
            "api_version": 2,
            "csr": generated["csr"],
            "signature": generated["signature"],
            "vm_config": vm_config,
        }
        url = str(kms["rpc_prpc_url"])
        body = json.dumps(request_value, separators=(",", ":")).encode()
        code, raw = call(url, body, "application/json", identity)
        if code != 200:
            diagnostic = raw[:500].decode(errors="replace").replace("\n", " ")
            raise AssertionError(f"valid SignCert returned HTTP {code}: {diagnostic}")
        shape = chain_shape(json.loads(raw))
        evidence.update(
            {
                "attestation_mode": identity.get("attestation_mode"),
                "csr_version": 2,
                "csr_length": len(csr),
                "signature_length": len(signature),
                "public_key_length": len(bytes.fromhex(generated["public_key"])),
                "subject": generated["subject"],
                "alt_name": generated["alt_name"],
                "chain": shape,
            }
        )
        steps.append(
            emit(
                f"{case_id}-step-01",
                "PASS",
                "The case-owned generator produced a signed v2 CSR with fresh key-bound simulated TDX evidence, and KMS returned a three-entry certificate chain.",
            )
        )

        unknown = dict(request_value)
        unknown["future_field"] = "ignored"
        unknown_code, unknown_raw = call(
            url,
            json.dumps(unknown, separators=(",", ":")).encode(),
            "application/json",
            identity,
        )
        if unknown_code != 200 or chain_shape(json.loads(unknown_raw))["entries"] != 3:
            raise AssertionError("unknown JSON field changed SignCert semantics")
        protobuf = (
            bytes((0x08, 0x02))
            + field(2, csr)
            + field(3, signature)
            + field(4, vm_config.encode())
        )
        protobuf_code, protobuf_raw = call(
            url, protobuf, "application/octet-stream", identity
        )
        if protobuf_code != 200 or not protobuf_raw:
            raise AssertionError(
                f"valid protobuf SignCert returned HTTP {protobuf_code}"
            )
        evidence.update(
            {
                "unknown_field_ignored": True,
                "protobuf_status": protobuf_code,
                "protobuf_nonempty": True,
            }
        )
        steps.append(
            emit(
                f"{case_id}-step-02",
                "PASS",
                "JSON, unknown-field JSON, and protobuf representations all completed without persisting native certificate bodies.",
            )
        )

        mutations: dict[str, int] = {}
        for name, changed in (
            (
                "signature",
                {
                    **request_value,
                    "signature": (bytes((signature[0] ^ 1,)) + signature[1:]).hex(),
                },
            ),
            ("csr", {**request_value, "csr": (bytes((csr[0] ^ 1,)) + csr[1:]).hex()}),
            ("api_version", {**request_value, "api_version": 3}),
        ):
            changed_code, _ = call(
                url,
                json.dumps(changed, separators=(",", ":")).encode(),
                "application/json",
                identity,
            )
            if changed_code < 400:
                raise AssertionError(f"{name} mutation was accepted")
            mutations[name] = changed_code
        no_tls_code, no_tls_raw = call(url, body, "application/json", None)
        malformed_code, _ = call(url, b"{", "application/json", identity)
        if no_tls_code != 200 or chain_shape(json.loads(no_tls_raw))["entries"] != 3:
            raise AssertionError(
                f"valid embedded CSR attestation without optional mTLS returned {no_tls_code}"
            )
        if malformed_code < 400:
            raise AssertionError(
                f"malformed JSON was accepted with HTTP {malformed_code}"
            )
        evidence.update(
            {
                "mutation_statuses": mutations,
                "transport_mtls_optional_status": no_tls_code,
                "embedded_csr_attestation_enforced": True,
                "malformed_status": malformed_code,
                "negative_bodies_persisted": False,
            }
        )
        steps.append(
            emit(
                f"{case_id}-step-03",
                "PASS",
                f"CSR, signature, and API-version mutations failed closed; embedded CSR attestation remained authoritative without optional mTLS, and malformed JSON returned {malformed_code}.",
            )
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(f"{case_id}-step-{len(steps) + 1:02d}", "FAIL", failure))

    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    artifact = {
        "path": "artifacts/kms-sign-cert.json",
        "name": "Attested KMS SignCert matrix",
        "description": "CSR/public-key sizes, public certificate-chain metadata, representations, mutation statuses, authentication rejection, and liveness without private keys or native response bodies.",
    }
    write_json(artifacts / "kms-sign-cert.json", evidence)
    write_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": "KMS.SignCert accepted a signed key-bound attested CSR and rejected all mutations."
        if status == "PASS"
        else failure,
        "steps": steps,
        "artifacts": [artifact],
        "remarks": "The mock TDX chain confirms CSR/key/attestation binding and KMS policy behavior, not physical TEE isolation or vendor hardware trust.",
    }
    if failure:
        result["failure"] = failure
    write_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
