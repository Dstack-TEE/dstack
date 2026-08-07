#!/usr/bin/env python3
"""Deterministic contract test for the lease-owned Gateway.RegisterCvm RPC."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def request(
    url: str,
    body: bytes,
    content_type: str = "application/json",
    context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    """Call one JSON or protobuf route and return a redacted-ready observation."""
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": content_type}, method="POST"
    )
    try:
        with urllib.request.urlopen(
            req, timeout=20, context=context or ssl._create_unverified_context()
        ) as response:
            raw = response.read()
            status = int(response.status)
            response_type = response.headers.get("Content-Type")
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = int(error.code)
        response_type = error.headers.get("Content-Type") if error.headers else None
    except urllib.error.URLError:
        raw = b""
        status = 0
        response_type = None
    parsed: Any = None
    if raw:
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return {
        "status": status,
        "body": parsed,
        "body_len": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "content_type": response_type,
        "_raw": raw,
    }


def public(value: dict[str, Any]) -> dict[str, Any]:
    """Remove raw response bytes before persisting an observation."""
    return {key: item for key, item in value.items() if key != "_raw"}


def varint(value: int) -> bytes:
    """Encode one protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode(fields: list[dict[str, Any]], payload: dict[str, str]) -> bytes:
    """Encode string request fields using the indexed field matrix."""
    output = bytearray()
    for field in fields:
        name = str(field["name"])
        if name not in payload:
            continue
        if field["type"] != "string":
            raise AssertionError(f"unsupported request field type: {field['type']}")
        raw = payload[name].encode()
        output.extend(varint((int(field["number"]) << 3) | 2))
        output.extend(varint(len(raw)))
        output.extend(raw)
    return bytes(output)


def wire_numbers(data: bytes) -> list[int]:
    """Return the top-level field numbers in a protobuf response."""
    numbers: list[int] = []
    offset = 0
    while offset < len(data):
        key = 0
        shift = 0
        while True:
            byte = data[offset]
            offset += 1
            key |= (byte & 0x7F) << shift
            if byte < 0x80:
                break
            shift += 7
        number, wire = key >> 3, key & 7
        numbers.append(number)
        if wire == 0:
            while data[offset] >= 0x80:
                offset += 1
            offset += 1
        elif wire == 2:
            length = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                length |= (byte & 0x7F) << shift
                if byte < 0x80:
                    break
                shift += 7
            offset += length
        else:
            raise AssertionError(f"unsupported protobuf wire type {wire}")
    return sorted(set(numbers))


def inventory(root: pathlib.Path) -> dict[str, Any]:
    """Load the authoritative Gateway.RegisterCvm field matrix."""
    document = json.loads((root / "api-inventory.json").read_text())
    found: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if (
                value.get("service") == "Gateway"
                and value.get("method") == "RegisterCvm"
            ):
                found.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    if len(found) != 1:
        raise RuntimeError("expected one Gateway.RegisterCvm inventory entry")
    return found[0]


def wg_public_key() -> str:
    """Generate a valid case-scoped WireGuard public key in memory."""
    result = subprocess.run(
        ["bash", "-c", "set -o pipefail; wg genkey | wg pubkey"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    key = result.stdout.strip()
    if result.returncode or len(key) != 44:
        raise RuntimeError("failed to generate a case-scoped WireGuard public key")
    return key


def require_response(value: dict[str, Any], fields: list[dict[str, Any]]) -> None:
    """Validate and redact a successful JSON registration response."""
    body = value["body"]
    if value["status"] != 200 or not isinstance(body, dict):
        raise AssertionError(f"registration failed with HTTP {value['status']}")
    missing = sorted(
        str(field["name"]) for field in fields if field["name"] not in body
    )
    if missing:
        raise AssertionError(f"registration response omitted fields: {missing}")
    if not isinstance(body.get("wg"), dict) or not isinstance(body.get("agent"), dict):
        raise AssertionError("response omitted WireGuard or agent configuration")
    if not isinstance(body.get("gateways"), list):
        raise AssertionError("response gateways was not a list")
    # Persist structure only; response values can contain configuration secrets.
    value["body"] = {
        "keys": sorted(body),
        "wg_keys": sorted(body["wg"]),
        "agent_keys": sorted(body["agent"]),
        "gateway_count": len(body["gateways"]),
    }


def main() -> int:
    """Execute the deterministic registration contract matrix."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != "tc-gw-gateway-001":
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    base = str(manifest["values"]["gateway"]["rpc_url"]).rstrip("/")
    registration_client = manifest["values"]["gateway"]["registration_client"]
    authenticated = ssl._create_unverified_context()
    authenticated.load_cert_chain(
        certfile=str(registration_client["cert"]),
        keyfile=str(registration_client["key"]),
    )
    route = f"{base}/Tproxy.RegisterCvm"
    contract = inventory(plan_root)
    key = wg_public_key()
    steps: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    status = "PASS"
    failure = ""

    def record(name: str, step_id: str, value: Any, description: str) -> None:
        atomic_json(artifacts_dir / name, value)
        artifacts.append(
            {
                "path": f"artifacts/{name}",
                "step_id": step_id,
                "name": name,
                "description": description,
            }
        )

    try:
        step = f"{case_id}-step-01"
        print(f"STEP {step} START", flush=True)
        invalid_route = request(route + "NoSuch", b"{}", context=authenticated)
        unauthenticated = request(route, b"{}")
        authenticated_empty = request(route, b"{}", context=authenticated)
        record(
            "step01-prerequisite.json",
            step,
            {
                "invalid_route": public(invalid_route),
                "unauthenticated": public(unauthenticated),
                "authenticated_empty": public(authenticated_empty),
            },
            "Reachability and rejection baseline.",
        )
        if (
            invalid_route["status"] < 400
            or (unauthenticated["status"] != 0 and unauthenticated["status"] < 400)
            or authenticated_empty["status"] < 400
        ):
            raise AssertionError(
                "invalid route or absent required identity was accepted"
            )
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "The mTLS listener rejected invalid routing and an unauthenticated registration.",
            }
        )
        print(f"STEP {step} END - PASS", flush=True)

        step = f"{case_id}-step-02"
        print(f"STEP {step} START", flush=True)
        valid_payload = {
            "client_public_key": key,
            "port_policy": {
                "ports": [{"port": 18080, "pp": True}, {"port": 15353, "pp": False}],
                "restrict_mode": True,
            },
        }
        valid = request(
            route,
            json.dumps(valid_payload, separators=(",", ":")).encode(),
            context=authenticated,
        )
        require_response(valid, contract["response_fields"])
        unknown = request(
            route,
            json.dumps(
                {
                    **valid_payload,
                    "__future_field": True,
                }
            ).encode(),
            context=authenticated,
        )
        require_response(unknown, contract["response_fields"])
        wrong_type = request(
            route,
            json.dumps({**valid_payload, "port_policy": "invalid"}).encode(),
            context=authenticated,
        )
        malformed_key = request(
            route,
            json.dumps(
                {
                    **valid_payload,
                    "client_public_key": "invalid",
                }
            ).encode(),
            context=authenticated,
        )
        invalid_port = request(
            route,
            json.dumps(
                {
                    **valid_payload,
                    "port_policy": {
                        "ports": [{"port": 70000, "pp": True}],
                        "restrict_mode": True,
                    },
                }
            ).encode(),
            context=authenticated,
        )
        if (
            wrong_type["status"] < 400
            or malformed_key["status"] < 400
            or invalid_port["status"] < 400
        ):
            raise AssertionError(
                "wrong-typed identity or malformed public key was accepted"
            )
        record(
            "step02-json-contract.json",
            step,
            {
                "valid": public(valid),
                "unknown_field": public(unknown),
                "wrong_type": public(wrong_type),
                "malformed_public_key": public(malformed_key),
                "out_of_range_port": public(invalid_port),
            },
            "JSON field and response-shape matrix.",
        )
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "Valid and forward-compatible JSON returned the documented structures; invalid values were rejected.",
            }
        )
        print(f"STEP {step} END - PASS", flush=True)

        step = f"{case_id}-step-03"
        print(f"STEP {step} START", flush=True)
        # The optional nested policy is covered in JSON. Its absence is the
        # protobuf default/presence row required by the field matrix.
        protobuf_payload = {"client_public_key": key}
        protobuf = request(
            route,
            encode(contract["request_fields"], protobuf_payload),
            "application/octet-stream",
            authenticated,
        )
        if protobuf["status"] != 200:
            raise AssertionError(
                f"protobuf registration failed with HTTP {protobuf['status']}"
            )
        numbers = wire_numbers(protobuf["_raw"])
        expected = sorted(int(field["number"]) for field in contract["response_fields"])
        if numbers != expected:
            raise AssertionError(f"protobuf fields {numbers} did not match {expected}")
        repeat = request(
            route, json.dumps(valid_payload).encode(), context=authenticated
        )
        require_response(repeat, contract["response_fields"])
        health = request(base + "/Tproxy.Info", b"{}", context=authenticated)
        if health["status"] != 200:
            raise AssertionError("Gateway.Info was unavailable after registration")
        record(
            "step03-protobuf-state.json",
            step,
            {
                "protobuf": {**public(protobuf), "field_numbers": numbers},
                "repeat": public(repeat),
                "health": public(health),
            },
            "Protobuf coverage, repeat behavior, and post-matrix availability.",
        )
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "Protobuf returned every top-level field, repeat registration succeeded, and Gateway.Info remained available.",
            }
        )
        print(f"STEP {step} END - PASS", flush=True)
        summary = "Gateway.RegisterCvm passed its isolated JSON/protobuf, invalid-input, repeat, response-structure, and availability matrix."
    except Exception as error:  # noqa: BLE001
        status = "FAIL"
        failure = str(error)
        summary = f"Gateway.RegisterCvm failed: {failure}"
        done = {item["id"] for item in steps}
        failed_written = False
        for number in (1, 2, 3):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id in done:
                continue
            steps.append(
                {
                    "id": step_id,
                    "status": "FAIL" if not failed_written else "NOT_RUN",
                    "observed": failure
                    if not failed_written
                    else "Not run after earlier failure.",
                }
            )
            failed_written = True

    atomic_json(artifacts_dir / "manifest.json", {"artifacts": artifacts})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "The prepared client certificate authenticates only to the lease-owned gateway and is never read or persisted by this harness; secret-bearing response values are reduced to structural metadata.",
        },
    )
    print(json.dumps({"status": status, "summary": summary}), flush=True)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
