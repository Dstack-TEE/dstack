#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regressions for promoted Gateway instance port-policy RPCs."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import ssl
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASES = {"tc-gw-admin-031", "tc-gw-admin-032", "tc-gw-admin-033"}
POLICY = {
    "ports": [
        {"port": 18080, "pp": False},
        {"port": 18443, "pp": True},
        {"port": 15353, "pp": False},
    ],
    "restrict_mode": True,
}
EXPECTED_PORTS = {15353, 18080, 18443}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def inventory_entry(root: pathlib.Path, service: str, method: str) -> dict[str, Any]:
    """Load the authoritative field matrix for one RPC method."""
    document = json.loads((root / "api-inventory.json").read_text(encoding="utf-8"))
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
        raise RuntimeError(f"expected one inventory entry for {service}.{method}")
    return matches[0]


def varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_request(fields: list[dict[str, Any]], payload: dict[str, Any]) -> bytes:
    """Encode a request body from the inventory field matrix."""
    output = bytearray()
    for field in fields:
        name = field["name"]
        if name not in payload:
            continue
        number = int(field["number"])
        kind = str(field["type"])
        if kind != "string":
            raise ValueError(f"unsupported request field type: {kind}")
        raw = str(payload[name]).encode()
        output.extend(varint((number << 3) | 2))
        output.extend(varint(len(raw)))
        output.extend(raw)
    return bytes(output)


def wire_field_numbers(data: bytes) -> list[int]:
    """Return the field numbers present in a protobuf response body."""
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
            raise ValueError(f"unsupported response wire type {wire}")
    return sorted(set(numbers))


def call(
    base: str,
    method: str,
    payload: Any,
    token: str | None,
    raw: bytes | None = None,
    content_type: str = "application/json",
) -> dict[str, Any]:
    """Call an admin RPC without persisting authorization material."""
    body = raw if raw is not None else json.dumps(payload).encode()
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{base}/{method}", data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(
            request, timeout=20, context=ssl._create_unverified_context()
        ) as response:
            response_body = response.read()
            status = int(response.status)
            response_type = response.headers.get("Content-Type")
    except urllib.error.HTTPError as error:
        response_body = error.read()
        status = int(error.code)
        response_type = error.headers.get("Content-Type") if error.headers else None
    parsed: Any = None
    if response_body:
        try:
            parsed = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    observation: dict[str, Any] = {
        "status": status,
        "body": parsed,
        "body_len": len(response_body),
        "body_sha256": hashlib.sha256(response_body).hexdigest(),
        "content_type": response_type,
    }
    if content_type == "application/octet-stream":
        observation["field_numbers"] = wire_field_numbers(response_body)
    return observation


def policy_ports(value: Any) -> set[int]:
    """Extract normalized port numbers from a returned policy."""
    if not isinstance(value, dict):
        return set()
    ports = value.get("ports")
    if not isinstance(ports, list):
        return set()
    return {
        item.get("port")
        for item in ports
        if isinstance(item, dict) and isinstance(item.get("port"), int)
    }


def is_empty_response(response: dict[str, Any]) -> bool:
    """Accept the current JSON encoding and protobuf encoding of Empty."""
    return response["status"] == 200 and (
        response["body_len"] == 0 or response.get("body") in ({}, None)
    )


def assert_admin_policy(response: dict[str, Any]) -> None:
    """Require the expected effective and admin override policy."""
    body = response.get("body")
    if (
        response["status"] != 200
        or not isinstance(body, dict)
        or body.get("source") != "admin"
    ):
        raise AssertionError("GetInstancePortPolicy did not report an admin policy")
    if (
        policy_ports(body.get("admin_override")) != EXPECTED_PORTS
        or policy_ports(body.get("effective")) != EXPECTED_PORTS
    ):
        raise AssertionError("port-policy readback did not contain the requested ports")


def assert_no_policy(response: dict[str, Any]) -> None:
    """Require the documented no-policy response."""
    body = response.get("body")
    if response["status"] != 200 or not isinstance(body, dict):
        raise AssertionError("GetInstancePortPolicy failed")
    if (
        body.get("source") != "none"
        or body.get("admin_override") is not None
        or body.get("effective") is not None
    ):
        raise AssertionError("port policy remained after clear")


def main() -> int:
    """Execute one promoted instance port-policy regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASES:
        raise SystemExit(f"unsupported promoted port-policy case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    instance_id = str(gateway["registered_instance_id"])
    base = str(gateway["admin_url"]).rstrip("/")
    auth = (
        pathlib.Path(gateway["admin_auth_token_file"])
        .read_text(encoding="utf-8")
        .strip()
    )
    if not instance_id or not auth:
        raise RuntimeError("gateway registered instance or admin token is unavailable")
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    step_ids = [f"{case_id}-step-{number:02d}" for number in (1, 2, 3)]
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
                "name": name.removesuffix(".json").replace("-", " ").title(),
                "description": description,
            }
        )

    try:
        print(f"STEP {step_ids[0]} START", flush=True)
        baseline = call(
            base, "Admin.GetInstancePortPolicy", {"instance_id": instance_id}, auth
        )
        unauthorized = call(
            base, "Admin.GetInstancePortPolicy", {"instance_id": instance_id}, None
        )
        if baseline["status"] != 200 or unauthorized["status"] not in (401, 403):
            raise AssertionError(
                "port-policy prerequisite or authorization enforcement failed"
            )
        record(
            "step01-prereq.json",
            step_ids[0],
            {"baseline": baseline, "unauthorized": unauthorized},
            "Authenticated baseline and authorization enforcement.",
        )
        steps.append(
            {
                "id": step_ids[0],
                "status": "PASS",
                "observed": "Registered instance policy was readable and the admin endpoint required authentication.",
            }
        )
        print(f"STEP {step_ids[0]} END - PASS", flush=True)

        print(f"STEP {step_ids[1]} START", flush=True)
        set_response = call(
            base,
            "Admin.SetInstancePortPolicy",
            {"instance_id": instance_id, "policy": POLICY},
            auth,
        )
        readback = call(
            base, "Admin.GetInstancePortPolicy", {"instance_id": instance_id}, auth
        )
        malformed = call(
            base, "Admin.SetInstancePortPolicy", {}, auth, raw=b'{"instance_id":'
        )
        object_form = call(
            base,
            "Admin.SetInstancePortPolicy",
            {
                "instance_id": instance_id,
                "policy": {"ports": [{"port": "invalid", "pp": False}]},
            },
            auth,
        )
        no_auth = call(
            base,
            "Admin.SetInstancePortPolicy",
            {"instance_id": instance_id, "policy": POLICY},
            None,
        )
        if not is_empty_response(set_response):
            raise AssertionError("SetInstancePortPolicy did not return Empty")
        assert_admin_policy(readback)
        if (
            malformed["status"] < 400
            or object_form["status"] < 400
            or no_auth["status"] not in (401, 403)
        ):
            raise AssertionError(
                "invalid or unauthenticated SetInstancePortPolicy was accepted"
            )
        behavior: dict[str, Any] = {
            "set": set_response,
            "readback": readback,
            "malformed": malformed,
            "object_form": object_form,
            "unauthorized": no_auth,
        }
        if case_id == "tc-gw-admin-032":
            cleared = call(
                base,
                "Admin.ClearInstancePortPolicy",
                {"instance_id": instance_id},
                auth,
            )
            after_clear = call(
                base, "Admin.GetInstancePortPolicy", {"instance_id": instance_id}, auth
            )
            clear_malformed = call(
                base, "Admin.ClearInstancePortPolicy", {}, auth, raw=b'{"instance_id":'
            )
            clear_no_auth = call(
                base,
                "Admin.ClearInstancePortPolicy",
                {"instance_id": instance_id},
                None,
            )
            if not is_empty_response(cleared):
                raise AssertionError("ClearInstancePortPolicy did not return Empty")
            assert_no_policy(after_clear)
            if clear_malformed["status"] < 400 or clear_no_auth["status"] not in (
                401,
                403,
            ):
                raise AssertionError(
                    "invalid or unauthenticated ClearInstancePortPolicy was accepted"
                )
            behavior.update(
                {
                    "clear": cleared,
                    "after_clear": after_clear,
                    "clear_malformed": clear_malformed,
                    "clear_unauthorized": clear_no_auth,
                }
            )
        elif case_id == "tc-gw-admin-033":
            # The read itself is the tested action here, so exercise its own
            # request contract rather than inheriting the setter's coverage.
            entry = inventory_entry(plan_root, "Admin", "GetInstancePortPolicy")
            documented = {field["name"] for field in entry["response_fields"]}
            body = readback["body"]
            missing = sorted(documented - set(body if isinstance(body, dict) else {}))
            if missing:
                raise AssertionError(
                    f"GetInstancePortPolicy response omitted fields: {missing}"
                )
            if (
                body.get("source") != "admin"
                or baseline["body"].get("source") != "none"
            ):
                raise AssertionError(
                    "GetInstancePortPolicy did not report the source transition"
                )
            # The response is derived from stored state and carries no clock, so
            # a repeated read is byte-identical; assert it rather than assume it.
            repeated = call(
                base, "Admin.GetInstancePortPolicy", {"instance_id": instance_id}, auth
            )
            if repeated["body_sha256"] != readback["body_sha256"]:
                raise AssertionError(
                    "repeated GetInstancePortPolicy was not deterministic"
                )
            unknown_field = call(
                base,
                "Admin.GetInstancePortPolicy",
                {"instance_id": instance_id, "unknown_field_probe": True},
                auth,
            )
            if unknown_field["body_sha256"] != readback["body_sha256"]:
                raise AssertionError(
                    "GetInstancePortPolicy did not ignore an unknown field"
                )
            protobuf = call(
                base,
                "Admin.GetInstancePortPolicy",
                None,
                auth,
                raw=encode_request(
                    entry["request_fields"], {"instance_id": instance_id}
                ),
                content_type="application/octet-stream",
            )
            numbers = {int(field["number"]) for field in entry["response_fields"]}
            required = {
                int(field["number"])
                for field in entry["response_fields"]
                if field["name"] in ("effective", "source", "admin_override")
            }
            if (
                protobuf["status"] != 200
                or not set(protobuf["field_numbers"]).issubset(numbers)
                or not required.issubset(set(protobuf["field_numbers"]))
            ):
                raise AssertionError(
                    "protobuf GetInstancePortPolicy did not return the documented fields"
                )
            empty_instance = call(
                base, "Admin.GetInstancePortPolicy", {"instance_id": ""}, auth
            )
            unknown_instance = call(
                base,
                "Admin.GetInstancePortPolicy",
                {"instance_id": f"absent-instance-{os.urandom(6).hex()}"},
                auth,
            )
            wrong_type = call(
                base, "Admin.GetInstancePortPolicy", {"instance_id": 1}, auth
            )
            get_malformed = call(
                base, "Admin.GetInstancePortPolicy", {}, auth, raw=b'{"instance_id":'
            )
            get_no_auth = call(
                base, "Admin.GetInstancePortPolicy", {"instance_id": instance_id}, None
            )
            if (
                empty_instance["status"] < 400
                or unknown_instance["status"] < 400
                or wrong_type["status"] < 400
                or get_malformed["status"] < 400
                or get_no_auth["status"] not in (401, 403)
            ):
                raise AssertionError("GetInstancePortPolicy rejection contract failed")
            behavior.update(
                {
                    "baseline": baseline,
                    "repeated": repeated,
                    "unknown_field": unknown_field,
                    "protobuf": protobuf,
                    "empty_instance": empty_instance,
                    "unknown_instance": unknown_instance,
                    "wrong_type": wrong_type,
                    "get_malformed": get_malformed,
                    "get_unauthorized": get_no_auth,
                }
            )
        record(
            "step02-behavior.json",
            step_ids[1],
            behavior,
            "Valid state transition, readback, malformed input, object-form rejection, and authorization behavior.",
        )
        steps.append(
            {
                "id": step_ids[1],
                "status": "PASS",
                "observed": "Port-policy mutation and readback matched the documented scalar-port contract with negative-path enforcement.",
            }
        )
        print(f"STEP {step_ids[1]} END - PASS", flush=True)

        print(f"STEP {step_ids[2]} START", flush=True)
        if case_id != "tc-gw-admin-032":
            cleared = call(
                base,
                "Admin.ClearInstancePortPolicy",
                {"instance_id": instance_id},
                auth,
            )
            if not is_empty_response(cleared):
                raise AssertionError("cleanup ClearInstancePortPolicy failed")
        final_state = call(
            base, "Admin.GetInstancePortPolicy", {"instance_id": instance_id}, auth
        )
        assert_no_policy(final_state)
        repeat_clear = call(
            base, "Admin.ClearInstancePortPolicy", {"instance_id": instance_id}, auth
        )
        if not is_empty_response(repeat_clear):
            raise AssertionError("idempotent ClearInstancePortPolicy failed")
        record(
            "step03-cleanup.json",
            step_ids[2],
            {"final_state": final_state, "repeat_clear": repeat_clear},
            "Deterministic cleanup and idempotent clear state.",
        )
        steps.append(
            {
                "id": step_ids[2],
                "status": "PASS",
                "observed": "Policy state was restored to none and repeated clear remained idempotent.",
            }
        )
        print(f"STEP {step_ids[2]} END - PASS", flush=True)
    except Exception as error:
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        if len(steps) < 3:
            steps.append(
                {"id": step_ids[len(steps)], "status": "FAIL", "observed": failure}
            )
    finally:
        try:
            call(
                base,
                "Admin.ClearInstancePortPolicy",
                {"instance_id": instance_id},
                auth,
            )
        except Exception:
            pass
    while len(steps) < 3:
        steps.append(
            {
                "id": step_ids[len(steps)],
                "status": "NOT_RUN",
                "observed": "Not run after an earlier failure.",
            }
        )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Gateway instance port-policy deterministic regression passed."
            if status == "PASS"
            else f"Gateway instance port-policy deterministic regression failed: {failure}",
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "Uses the manifest registered instance, scalar port arrays, authenticated admin calls, bounded negative checks, and deterministic cleanup.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
