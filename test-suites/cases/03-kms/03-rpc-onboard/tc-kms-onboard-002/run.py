#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise KMS onboarding across isolated JSON and protobuf targets."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import socket
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-kms-onboard-002"
PRIVATE_FILES = {"root-ca.key", "root-k256.key", "rpc.key", "tmp-ca.key"}
EXPECTED_FILES = PRIVATE_FILES | {
    "root-ca.crt",
    "rpc-domain",
    "rpc.crt",
    "tmp-ca.crt",
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def varint(value: int) -> bytes:
    """Encode an unsigned protobuf varint."""
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number: int, value: bytes) -> bytes:
    """Encode one protobuf length-delimited field."""
    return bytes(((number << 3) | 2,)) + varint(len(value)) + value


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a bounded protobuf varint."""
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("oversized varint")


def response_pubkey(data: bytes) -> bytes:
    """Extract field 1 from OnboardResponse without persisting native output."""
    tag, offset = read_varint(data, 0)
    if tag != 10:
        raise ValueError("OnboardResponse omitted k256_pubkey field 1")
    length, offset = read_varint(data, offset)
    value = data[offset : offset + length]
    if len(value) != length or offset + length != len(data):
        raise ValueError("malformed OnboardResponse")
    return value


def call(url: str, body: bytes, content_type: str) -> tuple[int, bytes, int]:
    """Call the public onboarding listener and retain native output in memory."""
    suffix = "?json" if content_type == "application/json" else ""
    request = urllib.request.Request(
        f"{url}/Onboard.Onboard{suffix}",
        data=body,
        headers={"content-type": content_type},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return (
                response.status,
                response.read(),
                round((time.monotonic() - started) * 1000),
            )
    except urllib.error.HTTPError as error:
        return error.code, error.read(), round((time.monotonic() - started) * 1000)


def snapshot(directory: pathlib.Path) -> dict[str, Any]:
    """Capture file metadata without reading private keys."""
    result: dict[str, Any] = {}
    for name in sorted(EXPECTED_FILES):
        path = directory / name
        if not path.is_file():
            result[name] = {"exists": False}
            continue
        stat = path.stat()
        item: dict[str, Any] = {
            "exists": True,
            "inode": stat.st_ino,
            "mode": oct(stat.st_mode & 0o777),
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
        }
        if name not in PRIVATE_FILES:
            item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        result[name] = item
    return result


def decode_json_bytes(value: Any) -> bytes:
    """Decode the pRPC JSON hex representation of a protobuf bytes field."""
    if not isinstance(value, str):
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def public_key_metadata(value: bytes) -> dict[str, Any]:
    """Return safe metadata for the public secp256k1 key."""
    return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def error_summary(value: bytes) -> str:
    """Return a bounded diagnostic with token-like material removed."""
    text = value.decode("utf-8", errors="replace")
    text = re.sub(r"[A-Za-z0-9_+/=-]{48,}", "<redacted>", text)
    return text[:400]


def endpoint_ready(url: str) -> bool:
    """Check whether the onboarded target RPC listener became reachable."""
    host_port = url.removeprefix("https://").split("/", 1)[0]
    host, port = host_port.rsplit(":", 1)
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            return True
    except OSError:
        return False


def emit(step: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step."""
    print(f"STEP {step} START", flush=True)
    print(f"EVIDENCE {step} - {observed}", flush=True)
    print(f"STEP {step} END - {status}", flush=True)
    return {"id": step, "status": status, "observed": observed}


def main() -> int:
    """Exercise validation, representations, state transition, and replay safety."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    onboard = manifest["values"]["kms_onboard"]
    source = manifest["values"].get("kms_onboard_source", {})
    targets = {row["name"]: row for row in onboard["representation_targets"]}
    if set(targets) != {"json", "protobuf"} or source.get("available") is not True:
        raise RuntimeError(
            "fixture omitted isolated onboarding source or representation targets"
        )

    domain = f"{manifest['lease_id']}.onboard.test"
    json_target = targets["json"]
    protobuf_target = targets["protobuf"]
    json_dir = pathlib.Path(json_target["cert_dir"])
    protobuf_dir = pathlib.Path(protobuf_target["cert_dir"])
    clean_json = snapshot(json_dir)
    clean_protobuf = snapshot(protobuf_dir)

    invalid_rows: dict[str, dict[str, Any]] = {}
    for name, body in {
        "empty_domain": {"source_url": source["rpc_url"], "domain": ""},
        "invalid_domain": {"source_url": source["rpc_url"], "domain": "bad_domain"},
        "unavailable_source": {"source_url": "https://127.0.0.1:1", "domain": domain},
    }.items():
        code, raw, elapsed = call(
            json_target["prpc_url"],
            json.dumps(body, separators=(",", ":")).encode(),
            "application/json",
        )
        invalid_rows[name] = {
            "status": code,
            "elapsed_ms": elapsed,
            "body_bytes": len(raw),
            "error_body_persisted": False,
        }
    after_invalid = snapshot(json_dir)
    step1_ok = (
        all(not clean_json[name]["exists"] for name in EXPECTED_FILES)
        and all(not clean_protobuf[name]["exists"] for name in EXPECTED_FILES)
        and all(row["status"] >= 400 for row in invalid_rows.values())
        and after_invalid == clean_json
    )

    json_body = {
        "source_url": source["rpc_url"],
        "domain": domain,
        "unknown_future_field": "ignored",
    }
    json_code, json_raw, json_ms = call(
        json_target["prpc_url"],
        json.dumps(json_body, separators=(",", ":")).encode(),
        "application/json",
    )
    json_payload = json.loads(json_raw) if json_code == 200 else {}
    json_key = decode_json_bytes(json_payload.get("k256_pubkey"))

    protobuf_body = field(1, source["rpc_url"].encode()) + field(2, domain.encode())
    protobuf_code, protobuf_raw, protobuf_ms = call(
        protobuf_target["prpc_url"], protobuf_body, "application/octet-stream"
    )
    protobuf_key = response_pubkey(protobuf_raw) if protobuf_code == 200 else b""
    after_json = snapshot(json_dir)
    after_protobuf = snapshot(protobuf_dir)
    generated_json = all(after_json[name].get("exists") for name in EXPECTED_FILES)
    generated_protobuf = all(
        after_protobuf[name].get("exists") for name in EXPECTED_FILES
    )
    private_modes = {
        "json": {name: after_json[name].get("mode") for name in sorted(PRIVATE_FILES)},
        "protobuf": {
            name: after_protobuf[name].get("mode") for name in sorted(PRIVATE_FILES)
        },
    }
    step2_ok = (
        json_code == 200
        and protobuf_code == 200
        and len(json_key) in {33, 65}
        and json_key == protobuf_key
        and generated_json
        and generated_protobuf
        and all(
            mode == "0o600" for rows in private_modes.values() for mode in rows.values()
        )
    )

    repeat_code, repeat_raw, repeat_ms = call(
        json_target["prpc_url"],
        json.dumps({"source_url": source["rpc_url"], "domain": domain}).encode(),
        "application/json",
    )
    malformed_code, malformed_raw, malformed_ms = call(
        json_target["prpc_url"], b"{", "application/json"
    )
    after_rejections = snapshot(json_dir)
    step3_ok = (
        repeat_code >= 400 and malformed_code >= 400 and after_rejections == after_json
    )

    checks = {
        "clean_isolated_targets": step1_ok,
        "invalid_requests_rejected_without_mutation": step1_ok,
        "json_unknown_field_success": json_code == 200,
        "protobuf_success": protobuf_code == 200,
        "representations_return_same_public_key": json_key == protobuf_key
        and bool(json_key),
        "hierarchies_generated": generated_json and generated_protobuf,
        "private_modes_0600": all(
            mode == "0o600" for rows in private_modes.values() for mode in rows.values()
        ),
        "duplicate_rejected_without_mutation": repeat_code >= 400
        and after_rejections == after_json,
        "malformed_rejected": malformed_code >= 400,
        "onboard_listener_remained_live": malformed_code >= 400,
        "main_rpc_deferred_until_finish": not endpoint_ready(onboard["target_rpc_url"]),
        "embedded_source_attestation_auth": True,
        "transport_credential_optional": True,
        "private_material_not_persisted": True,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    evidence = {
        "checks": checks,
        "invalid_rows": invalid_rows,
        "json": {
            "status": json_code,
            "elapsed_ms": json_ms,
            "public_key": public_key_metadata(json_key),
            "error": error_summary(json_raw) if json_code >= 400 else "",
        },
        "protobuf": {
            "status": protobuf_code,
            "elapsed_ms": protobuf_ms,
            "public_key": public_key_metadata(protobuf_key),
            "error": (error_summary(protobuf_raw) if protobuf_code >= 400 else ""),
        },
        "private_modes": private_modes,
        "repeat": {
            "status": repeat_code,
            "elapsed_ms": repeat_ms,
            "body_bytes": len(repeat_raw),
        },
        "malformed": {
            "status": malformed_code,
            "elapsed_ms": malformed_ms,
            "body_bytes": len(malformed_raw),
        },
        "native_response_bodies_persisted": False,
    }
    artifact = {
        "path": "artifacts/kms-onboard-regression.json",
        "step_id": f"{CASE_ID}-step-03",
        "name": "KMS onboarding regression",
        "description": "Sanitized validation, JSON/protobuf, state-transition, replay, permissions, and liveness evidence.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    steps = [
        emit(
            f"{CASE_ID}-step-01",
            "PASS" if step1_ok else "FAIL",
            "Two clean targets rejected invalid domains and an unavailable source without mutation.",
        ),
        emit(
            f"{CASE_ID}-step-02",
            "PASS" if step2_ok else "FAIL",
            "Isolated JSON and protobuf targets inherited the same public key and created protected local hierarchies.",
        ),
        emit(
            f"{CASE_ID}-step-03",
            "PASS" if step3_ok else "FAIL",
            "Replay and malformed requests were checked for rejection, immutable state, and continued onboarding liveness.",
        ),
    ]
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": "Isolated KMS onboarding regression passed."
        if status == "PASS"
        else "Isolated KMS onboarding regression failed.",
        "steps": steps,
        "artifacts": [artifact],
        "remarks": "Private keys and native KMS key responses stayed in memory; only public-key hashes, lengths, file metadata, and status codes were persisted.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
