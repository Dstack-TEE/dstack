#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise protected KMS key RPCs with a key-bound simulated RA client."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASES = {
    "tc-kms-kms-001": {
        "method": "KMS.GetAppKey",
        "json": {"api_version": 1, "vm_config": "{}"},
        "protobuf": bytes.fromhex("080112027b7d"),
        "fields": {
            "ca_cert": str,
            "disk_crypt_key": str,
            "env_crypt_key": str,
            "k256_key": str,
            "k256_signature": str,
            "tproxy_app_id": str,
            "gateway_app_id": str,
            "os_image_hash": str,
        },
    },
    "tc-kms-kms-002": {
        "method": "KMS.GetKmsKey",
        "json": {"vm_config": "{}"},
        "protobuf": bytes.fromhex("0a027b7d"),
        "fields": {"temp_ca_key": str, "keys": list},
    },
}
CASES["tc-kms-keys-certs-003"] = CASES["tc-kms-kms-002"]


def context(identity: dict[str, Any] | None) -> ssl.SSLContext:
    """Create a bounded test TLS context without exposing key material."""
    value = ssl.create_default_context()
    value.check_hostname = False
    value.verify_mode = ssl.CERT_NONE
    if identity:
        value.load_cert_chain(str(identity["cert"]), str(identity["key"]))
    return value


def call(
    url: str,
    method: str,
    body: bytes,
    content_type: str,
    identity: dict[str, Any] | None,
) -> tuple[int, bytes]:
    """Invoke one pRPC representation and retain its native body only in memory."""
    request = urllib.request.Request(
        f"{url}/{method}" + ("?json" if content_type == "application/json" else ""),
        data=body,
        headers={"content-type": content_type},
    )
    try:
        with urllib.request.urlopen(
            request, context=context(identity), timeout=90
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def safe_shape(payload: dict[str, Any], fields: dict[str, type]) -> dict[str, Any]:
    """Validate all documented fields and return only non-secret structural facts."""
    shape: dict[str, Any] = {}
    for name, kind in fields.items():
        if name not in payload or not isinstance(payload[name], kind):
            raise AssertionError(
                f"response field {name} is absent or has the wrong type"
            )
        value = payload[name]
        if kind is str and not value:
            raise AssertionError(f"response field {name} is empty")
        if kind is list and not value:
            raise AssertionError(f"response field {name} is empty")
        shape[name] = {
            "present": True,
            "type": kind.__name__,
            "nonempty": bool(value),
            "length": len(value),
        }
    return shape


def write_json(path: Path, value: Any) -> None:
    """Write deterministic JSON evidence."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def emit(step: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step."""
    print(f"STEP {step} START", flush=True)
    print(f"EVIDENCE {step} - {observed}", flush=True)
    print(f"STEP {step} END - {status}", flush=True)
    return {"id": step, "status": status, "observed": observed}


def main() -> int:
    """Execute one protected KMS key RPC matrix."""
    case_id = os.environ.get("DSTACK_TEST_CASE_ID", "")
    if case_id not in CASES:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values") or {}
    identity = values.get("kms_attested_client")
    kms = values.get("kms") or {}
    spec = CASES[case_id]
    started = time.monotonic()
    status = "FAIL"
    failure = ""
    steps: list[dict[str, str]] = []
    evidence: dict[str, Any] = {
        "attestation_mode": identity.get("attestation_mode")
        if isinstance(identity, dict)
        else None,
        "native_responses_persisted": False,
    }
    try:
        if (
            not isinstance(identity, dict)
            or identity.get("attestation_mode") != "mock-dstack-tdx"
        ):
            raise RuntimeError("fixture omitted its key-bound simulated RA client")
        if not all(
            Path(str(identity.get(key, ""))).is_file()
            for key in ("cert", "key", "ca_cert", "trust_root")
        ):
            raise RuntimeError("fixture attested-client paths are incomplete")
        url = str(kms["rpc_prpc_url"])
        method = str(spec["method"])
        request_value = dict(spec["json"])
        request_value["vm_config"] = str(identity["vm_config"])
        body = json.dumps(request_value, separators=(",", ":")).encode()
        code, raw = call(url, method, body, "application/json", identity)
        if code != 200:
            diagnostic = raw[:500].decode(errors="replace").replace("\n", " ")
            raise AssertionError(
                f"valid JSON request returned HTTP {code}: {diagnostic}"
            )
        payload = json.loads(raw)
        shape = safe_shape(payload, spec["fields"])
        evidence["json_shape"] = shape
        if case_id == "tc-kms-keys-certs-003":
            keys = payload.get("keys")
            if not isinstance(keys, list) or len(keys) != 1:
                raise AssertionError("GetKmsKey did not return the current root key")
            fingerprints = []
            for item in keys:
                if not isinstance(item, dict):
                    raise AssertionError("GetKmsKey returned a malformed key entry")
                ca_key = item.get("ca_key")
                k256_key = item.get("k256_key")
                if not isinstance(ca_key, str) or not isinstance(k256_key, str):
                    raise AssertionError("GetKmsKey key entry omitted private fields")
                fingerprints.append(
                    hashlib.sha256(f"{ca_key}:{k256_key}".encode()).hexdigest()
                )
            evidence["current_key_set"] = {
                "key_count": 1,
                "entry_complete": len(fingerprints) == 1,
                "private_material_persisted": False,
            }
        steps.append(
            emit(
                f"{case_id}-step-01",
                "PASS",
                "The lease-owned KMS accepted a certificate whose public key was bound to seed-matched simulated TDX evidence.",
            )
        )

        second_code, second_raw = call(url, method, body, "application/json", identity)
        if second_code != 200 or second_raw != raw:
            raise AssertionError("repeated protected request was not byte-stable")
        unknown = dict(request_value)
        unknown["future_field"] = "ignored"
        unknown_code, unknown_raw = call(
            url,
            method,
            json.dumps(unknown, separators=(",", ":")).encode(),
            "application/json",
            identity,
        )
        if (
            unknown_code != 200
            or safe_shape(json.loads(unknown_raw), spec["fields"]) != shape
        ):
            raise AssertionError("unknown JSON field changed known response semantics")
        vm_config_bytes = request_value["vm_config"].encode()
        if len(vm_config_bytes) > 127:
            raise AssertionError(
                "fixture vm_config exceeds the single-byte protobuf boundary"
            )
        if case_id == "tc-kms-kms-001":
            protobuf_body = (
                bytes((0x08, 0x01, 0x12, len(vm_config_bytes))) + vm_config_bytes
            )
        else:
            protobuf_body = bytes((0x0A, len(vm_config_bytes))) + vm_config_bytes
        protobuf_code, protobuf_raw = call(
            url, method, protobuf_body, "application/octet-stream", identity
        )
        if protobuf_code != 200 or not protobuf_raw:
            raise AssertionError(
                f"valid protobuf request returned HTTP {protobuf_code} or an empty body"
            )
        evidence.update(
            {
                "repeat_byte_stable": True,
                "unknown_field_ignored": True,
                "protobuf_status": protobuf_code,
                "protobuf_nonempty": True,
            }
        )
        steps.append(
            emit(
                f"{case_id}-step-02",
                "PASS",
                "JSON and protobuf succeeded, every documented response field was nonempty, repetition was byte-stable, and an unknown JSON field preserved known semantics.",
            )
        )

        unauth_code, _ = call(url, method, body, "application/json", None)
        malformed_code, _ = call(url, method, b"{", "application/json", identity)
        if unauth_code < 400 or malformed_code < 400:
            raise AssertionError(
                f"negative rows did not fail closed: unauth={unauth_code}, malformed={malformed_code}"
            )
        evidence.update(
            {
                "unauthenticated_status": unauth_code,
                "malformed_status": malformed_code,
                "negative_response_bodies_persisted": False,
            }
        )
        steps.append(
            emit(
                f"{case_id}-step-03",
                "PASS",
                f"Missing attestation context returned HTTP {unauth_code}; malformed JSON returned HTTP {malformed_code}; the service remained available.",
            )
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(f"{case_id}-step-{len(steps) + 1:02d}", "FAIL", failure))

    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    write_json(artifacts / "kms-attested-rpc.json", evidence)
    artifact = {
        "path": "artifacts/kms-attested-rpc.json",
        "name": "Protected KMS RPC structural evidence",
        "description": "Attestation mode, status codes, documented response shape, representation, determinism, and negative rows without native key material.",
    }
    write_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": f"{spec['method']} passed with a key-bound simulated RA client."
        if status == "PASS"
        else failure,
        "steps": steps,
        "artifacts": [artifact],
        "remarks": "The simulated TDX certificate confirms functional attestation routing, key binding, authorization, schema handling, and fail-closed behavior; it does not assert physical isolation or vendor hardware trust.",
    }
    if failure:
        result["failure"] = failure
    write_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
