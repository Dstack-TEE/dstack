#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic DstackGuest.Verify signature-verification contract regression.

`Verify` is a pure function over material that only the guest can produce, so
the harness first calls `DstackGuest.Sign` to obtain a genuine signature and
public key for the lease-owned app key, then verifies that pair, then proves a
tampered signature and a tampered message are rejected.  Hard-coding a
signature would bind the case to one lease's derived key.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

CASE = "tc-gos-dstackguest-008"
SERVICE = "DstackGuest"
# `k256` aliases `secp256k1`; `secp256k1_prehashed` requires exactly 32 bytes,
# which the lease-derived probe message always satisfies.
ALGORITHMS = ("ed25519", "secp256k1", "k256", "secp256k1_prehashed")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def length_delimited(number: int, raw: bytes) -> bytes:
    """Encode one length-delimited protobuf field."""
    return varint((number << 3) | 2) + varint(len(raw)) + raw


def decode_wire(data: bytes) -> dict[int, list[Any]]:
    """Decode a bounded protobuf response into field-number buckets."""
    values: dict[int, list[Any]] = {}
    offset = 0
    while offset < len(data):
        key = shift = 0
        while True:
            byte = data[offset]
            offset += 1
            key |= (byte & 0x7F) << shift
            if byte < 0x80:
                break
            shift += 7
        number, wire = key >> 3, key & 7
        if wire == 0:
            value = shift = 0
            while True:
                byte = data[offset]
                offset += 1
                value |= (byte & 0x7F) << shift
                if byte < 0x80:
                    break
                shift += 7
        elif wire == 2:
            length = shift = 0
            while True:
                byte = data[offset]
                offset += 1
                length |= (byte & 0x7F) << shift
                if byte < 0x80:
                    break
                shift += 7
            value = data[offset : offset + length]
            offset += length
        else:
            raise AssertionError(f"unsupported response wire type {wire}")
        values.setdefault(number, []).append(value)
    return values


def call(socket: str, route: str, content_type: str, body: bytes) -> tuple[int, bytes]:
    """Call one unix-socket pRPC endpoint."""
    marker = b"\nDSTACK_HTTP_STATUS:"
    process = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--unix-socket",
            socket,
            "--request",
            "POST",
            "--header",
            f"Content-Type: {content_type}",
            "--data-binary",
            "@-",
            "--write-out",
            marker.decode() + "%{http_code}",
            "http://localhost" + route,
        ],
        input=body,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.decode(errors="replace")[-1000:])
    response, code = process.stdout.rsplit(marker, 1)
    return int(code), response


def inventory_entry(root: pathlib.Path, service: str, method: str) -> dict[str, Any]:
    """Load the authoritative API inventory entry for one method."""
    document = json.loads((root / "api-inventory.json").read_text())
    matches: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("service") == service and value.get("method") == method:
                matches.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    if len(matches) != 1:
        raise AssertionError(f"expected one inventory entry for {service}.{method}")
    return matches[0]


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a protobuf varint from a buffer."""
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def structured_error(body: bytes) -> str:
    """Return the structured error of a rejected pRPC response.

    A rejection is framed in the representation of its request: a JSON request
    is answered with an `error` member, while a binary request is answered with
    a protobuf message whose field 1 carries the message.
    """
    if body[:1] == b"\x0a":
        length, offset = read_varint(body, 1)
        text = body[offset : offset + length].decode(errors="replace")
        if text:
            return text
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise AssertionError("rejection was not structured JSON or protobuf") from error
    message = value.get("error")
    if not isinstance(message, str) or not message:
        raise AssertionError("rejection omitted a structured error")
    return message


def flip_first_byte(raw: bytes) -> bytes:
    """Return the value with its first byte flipped."""
    mutated = bytearray(raw)
    mutated[0] ^= 0x01
    return bytes(mutated)


class Verifier:
    """Drive Sign/Verify over both pRPC representations for one fixture."""

    def __init__(self, socket: str, route: str, fields: list[dict[str, Any]]) -> None:
        """Bind the harness to the lease-owned socket and Verify route."""
        self.socket = socket
        self.route = route
        self.numbers = {field["name"]: int(field["number"]) for field in fields}

    def sign(self, sign_route: str, algorithm: str, data: bytes) -> tuple[bytes, bytes]:
        """Produce a genuine signature and public key for one algorithm."""
        payload = {"algorithm": algorithm, "data": data.hex()}
        code, body = call(
            self.socket, sign_route, "application/json", json.dumps(payload).encode()
        )
        if code != 200:
            raise AssertionError(f"Sign({algorithm}) returned HTTP {code}")
        value = json.loads(body)
        for name in ("signature", "signature_chain", "public_key"):
            if name not in value:
                raise AssertionError(f"Sign({algorithm}) omitted {name}")
        return bytes.fromhex(value["signature"]), bytes.fromhex(value["public_key"])

    def verify_json(self, payload: dict[str, Any]) -> tuple[int, bytes]:
        """Send one JSON Verify request."""
        return call(
            self.socket, self.route, "application/json", json.dumps(payload).encode()
        )

    def verify_protobuf(self, payload: dict[str, Any], extra: bytes = b"") -> bytes:
        """Send one binary protobuf Verify request and return the raw response."""
        body = b""
        for name in ("algorithm", "data", "signature", "public_key"):
            raw = payload[name]
            body += length_delimited(
                self.numbers[name], raw.encode() if isinstance(raw, str) else raw
            )
        code, response = call(
            self.socket, self.route, "application/octet-stream", body + extra
        )
        if code != 200:
            raise AssertionError(f"protobuf Verify returned HTTP {code}")
        return response

    def valid_flag(self, response: bytes) -> bool:
        """Read the `valid` flag from a protobuf VerifyResponse."""
        wire = decode_wire(response)
        # proto3 omits a false bool, so an empty body is a well-formed false.
        return bool(wire.get(1, [0])[0])


def request_payload(algorithm: str, data: bytes, signature: bytes, key: bytes) -> dict:
    """Build a JSON-shaped Verify payload with hex-encoded byte fields."""
    return {
        "algorithm": algorithm,
        "data": data.hex(),
        "signature": signature.hex(),
        "public_key": key.hex(),
    }


def roundtrip(client: Verifier, sign_route: str, algorithm: str, data: bytes) -> dict:
    """Sign with one algorithm, then verify genuine and tampered material."""
    signature, key = client.sign(sign_route, algorithm, data)
    payload = request_payload(algorithm, data, signature, key)
    code, body = client.verify_json(payload)
    if code != 200 or json.loads(body).get("valid") is not True:
        raise AssertionError(f"{algorithm}: genuine signature was not accepted")
    if not client.valid_flag(
        client.verify_protobuf(
            {
                "algorithm": algorithm,
                "data": data,
                "signature": signature,
                "public_key": key,
            }
        )
    ):
        raise AssertionError(
            f"{algorithm}: protobuf verification of a genuine "
            "signature returned valid=false"
        )
    tampered = request_payload(algorithm, data, flip_first_byte(signature), key)
    tampered_code, tampered_body = client.verify_json(tampered)
    if tampered_code != 200 or json.loads(tampered_body).get("valid") is not False:
        raise AssertionError(f"{algorithm}: a tampered signature was not rejected")
    if client.valid_flag(
        client.verify_protobuf(
            {
                "algorithm": algorithm,
                "data": data,
                "signature": flip_first_byte(signature),
                "public_key": key,
            }
        )
    ):
        raise AssertionError(
            f"{algorithm}: protobuf verification accepted a tampered signature"
        )
    altered = request_payload(algorithm, flip_first_byte(data), signature, key)
    altered_code, altered_body = client.verify_json(altered)
    if altered_code != 200 or json.loads(altered_body).get("valid") is not False:
        raise AssertionError(f"{algorithm}: a tampered message was not rejected")
    return {
        "signature_bytes": len(signature),
        "public_key_bytes": len(key),
        "public_key_sha256": hashlib.sha256(key).hexdigest(),
        "genuine_json_valid": True,
        "genuine_protobuf_valid": True,
        "tampered_signature_valid": False,
        "tampered_message_valid": False,
    }


def negatives(
    client: Verifier, algorithm: str, data: bytes, signature: bytes, key: bytes
) -> dict[str, Any]:
    """Exercise the rejection contract of Verify."""
    base = request_payload(algorithm, data, signature, key)
    observed: dict[str, Any] = {}
    for name, payload in (
        ("unsupported_algorithm", {**base, "algorithm": "dstack-test-unsupported"}),
        ("absent_fields", {}),
        ("malformed_signature", {**base, "signature": "aabb"}),
        ("malformed_public_key", {**base, "public_key": "aabb"}),
        ("schema_invalid_algorithm", {**base, "algorithm": 123}),
    ):
        code, body = client.verify_json(payload)
        if code < 400:
            raise AssertionError(f"{name} was accepted with HTTP {code}")
        observed[name] = {"http": code, "error": structured_error(body)}
    code, body = call(client.socket, client.route, "application/json", b'{"algorithm":')
    if code < 400:
        raise AssertionError("malformed JSON framing was accepted")
    observed["malformed_json"] = {"http": code, "error": structured_error(body)}
    code, body = call(
        client.socket, client.route, "application/octet-stream", b"\x0a\xff"
    )
    if code < 400:
        raise AssertionError("malformed protobuf framing was accepted")
    observed["malformed_protobuf"] = {"http": code, "error": structured_error(body)}
    code, body = call(
        client.socket, client.route + "-invalid", "application/json", b"{}"
    )
    if code < 400:
        raise AssertionError("an unknown route was accepted")
    observed["invalid_route"] = {"http": code, "error": structured_error(body)}
    return observed


def log_observation(path: str) -> dict[str, Any]:
    """Summarise the tail of the lease-owned simulator log without content."""
    log = pathlib.Path(path)
    if not log.is_file():
        return {"available": False}
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
    lowered = [line.lower() for line in lines]
    return {
        "available": True,
        "observed_lines": len(lines),
        "panic_lines": sum(1 for line in lowered if "panic" in line),
        "error_lines": sum(1 for line in lowered if "error" in line),
        "sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
    }


def main() -> int:
    """Run the DstackGuest.Verify regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    steps: list[dict[str, str]] = []
    failures: list[str] = []
    evidence: dict[str, Any] = {"case_id": case_id, "environment": "SIMULATION"}
    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        values = manifest["values"]
        service = values["services"][SERVICE]
        socket = str(service["socket"])
        if not pathlib.Path(socket).is_socket():
            raise AssertionError(f"fixture socket is not available: {socket}")
        verify_entry = inventory_entry(plan_root, SERVICE, "Verify")
        sign_entry = inventory_entry(plan_root, SERVICE, "Sign")
        route = str(service["route"]).replace("<Method>", "Verify")
        sign_route = str(service["route"]).replace("<Method>", "Sign")
        client = Verifier(socket, route, verify_entry["request_fields"])
        evidence["fixture"] = {
            "profile": manifest["profile"],
            "lease_id": manifest["lease_id"],
            "socket_available": True,
            "verify_request_fields": [
                field["name"] for field in verify_entry["request_fields"]
            ],
            "verify_response_fields": [
                field["name"] for field in verify_entry["response_fields"]
            ],
            "sign_response_fields": [
                field["name"] for field in sign_entry["response_fields"]
            ],
        }
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The lease-owned simulator socket, Sign route and indexed "
                "Verify contract were available with no run-scoped persistent object.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-01 - Proves the isolated guest listener and the "
            "indexed Verify contract were ready.",
            flush=True,
        )
        print(json.dumps(evidence["fixture"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        # Run-scoped, non-production probe message. 32 bytes satisfies the
        # secp256k1_prehashed length constraint recorded in api-inventory.json.
        data = hashlib.sha256(str(manifest["lease_id"]).encode()).digest()
        evidence["algorithms"] = {
            algorithm: roundtrip(client, sign_route, algorithm, data)
            for algorithm in ALGORITHMS
        }
        signature, key = client.sign(sign_route, "secp256k1", data)
        alias = request_payload("k256", data, signature, key)
        alias_code, alias_body = client.verify_json(alias)
        if alias_code != 200 or json.loads(alias_body).get("valid") is not True:
            raise AssertionError("k256 did not accept a secp256k1 signature")
        evidence["alias_k256_accepts_secp256k1"] = True
        ed_signature, ed_key = client.sign(sign_route, "ed25519", data)
        unknown = {
            **request_payload("ed25519", data, ed_signature, ed_key),
            f"unknown_{manifest['lease_id']}": 1,
        }
        unknown_code, unknown_body = client.verify_json(unknown)
        if unknown_code != 200 or json.loads(unknown_body).get("valid") is not True:
            raise AssertionError("an unknown JSON member changed the Verify result")
        if not client.valid_flag(
            client.verify_protobuf(
                {
                    "algorithm": "ed25519",
                    "data": data,
                    "signature": ed_signature,
                    "public_key": ed_key,
                },
                extra=length_delimited(9, b"unknown"),
            )
        ):
            raise AssertionError("an unknown protobuf field changed the Verify result")
        evidence["unknown_fields_ignored"] = True
        evidence["negatives"] = negatives(client, "ed25519", data, ed_signature, ed_key)
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Every indexed algorithm verified its own Sign output over "
                "JSON and protobuf, tampered signatures and messages returned "
                "valid=false, and unsupported or malformed input returned structured "
                "errors.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-02 - Proves genuine/tampered verification "
            "outcomes and structured rejection across both representations.",
            flush=True,
        )
        print(json.dumps(evidence["negatives"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)

        print(f"STEP {case_id}-step-03 START", flush=True)
        payload = request_payload("ed25519", data, ed_signature, ed_key)
        first_code, first_body = client.verify_json(payload)
        repeat_code, repeat_body = client.verify_json(payload)
        if first_code != 200 or repeat_code != 200:
            raise AssertionError("Verify was unavailable after invalid input")
        # Verify is a pure function of its request, so repeated identical
        # requests must be byte-identical: no timestamp or live state is
        # carried in VerifyResponse.
        if first_body != repeat_body:
            raise AssertionError("repeated identical Verify responses differed")
        evidence["repeat"] = {
            "http": repeat_code,
            "byte_identical": True,
            "sha256": hashlib.sha256(repeat_body).hexdigest(),
            "sensitive_response_persisted": False,
        }
        evidence["simulator_log"] = log_observation(str(manifest["values"]["log"]))
        if evidence["simulator_log"].get("panic_lines"):
            raise AssertionError("the simulator log recorded a panic")
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Repeated identical Verify calls were byte-identical and "
                "stateless, the listener survived every rejection, and bounded "
                "simulator diagnostics recorded no panic.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-03 - Proves stateless idempotent repeats, "
            "post-error availability and clean bounded diagnostics.",
            flush=True,
        )
        print(json.dumps(evidence["repeat"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as error:  # noqa: BLE001 - recorded as a case failure
        failures.append(f"{type(error).__name__}: {error}")
        completed = {step["id"] for step in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in completed:
                steps.append(
                    {"id": step_id, "status": "FAIL", "observed": failures[-1]}
                )
        print(failures[-1], file=sys.stderr, flush=True)

    status = "PASS" if not failures else "FAIL"
    evidence["status"] = status
    evidence["failure"] = failures[0] if failures else None
    artifact = {
        "name": "DstackGuest.Verify contract matrix",
        "path": "artifacts/dstackguest-verify-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Per-algorithm genuine and tampered verification outcomes, "
        "structured rejection statuses, repeat determinism, and bounded simulator "
        "diagnostics. Signature material stays in memory; only lengths and public "
        "key hashes are recorded.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "DstackGuest.Verify accepted every genuine Sign output over "
            "JSON and protobuf, rejected tampered signatures and messages, and "
            "returned structured errors for unsupported and malformed input."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "SIMULATION: this confirms the Verify RPC contract, not "
            "physical TEE trust properties. Verify is stateless, so the case leaves "
            "no run-scoped object behind.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
