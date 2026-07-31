#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Read-only ProxiedGuestApi SysInfo, NetworkInfo and ListContainers regression.

These three methods are proxied by the VMM to the lease-owned guest and mutate
nothing, so the harness may call each of them repeatedly.  None of them returns
a byte-stable response: `SysInfo` carries uptime, memory and load averages,
`NetworkInfo` carries interface byte counters and reorders its interface list
between calls, and `ListContainers` carries a human-readable `status` such as
"Up 3 minutes".  The repeat assertion therefore compares the identity of the
returned objects and requires the counters to be monotonic instead of demanding
byte equality, which would pass alone and fail under a parallel sweep.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any

# A VM id the lease does not own, used to prove the handler rejects an
# unresolvable but well-formed request.
UNKNOWN_VM_ID = "00000000-0000-4000-8000-000000000000"

CASES: dict[str, dict[str, Any]] = {
    "tc-gos-proxiedguestapi-002": {
        "method": "SysInfo",
        # os_name/os_version/kernel_version/cpu_model/num_cpus and the memory
        # and swap totals describe the guest, not its instantaneous load.
        "stable": [
            "os_name",
            "os_version",
            "kernel_version",
            "cpu_model",
            "num_cpus",
            "total_memory",
            "total_swap",
        ],
        "positive": ["num_cpus", "total_memory", "uptime"],
        "monotonic": ["uptime"],
        "nonempty_strings": ["os_name", "kernel_version", "cpu_model"],
        "repeated": {
            "disks": {"min": 1, "identity": ["name", "mount_point", "total_size"]}
        },
    },
    "tc-gos-proxiedguestapi-003": {
        "method": "NetworkInfo",
        "stable": ["dns_servers"],
        "positive": [],
        "monotonic": [],
        # `wg_info` is empty whenever the deployed app leaves the gateway
        # disabled, which the lease-owned compose does, so it is required to be
        # present rather than non-empty.
        "nonempty_strings": [],
        "repeated": {
            "gateways": {"min": 1, "identity": ["address"]},
            "interfaces": {
                "min": 1,
                "identity": ["name"],
                "monotonic": ["rx_bytes", "tx_bytes", "rx_errors", "tx_errors"],
                "nested": {"addresses": {"min": 1, "identity": ["address", "prefix"]}},
            },
        },
    },
    "tc-gos-proxiedguestapi-004": {
        "method": "ListContainers",
        "stable": [],
        "positive": [],
        "monotonic": [],
        "nonempty_strings": [],
        # `state` and `status` are live container state; only the immutable
        # identity of each container is compared across calls.
        "repeated": {
            "containers": {
                "min": 1,
                "identity": ["id", "names", "image", "image_id", "created"],
            }
        },
    },
}


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


def request(url: str, content_type: str, body: bytes) -> tuple[int, bytes]:
    """Call one ProxiedGuestApi method over the lease-owned VMM endpoint."""
    call = urllib.request.Request(
        url, data=body, headers={"content-type": content_type}
    )
    try:
        with urllib.request.urlopen(call, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_id(vm_id: str) -> bytes:
    """Encode the one-field `Id` protobuf request."""
    raw = vm_id.encode()
    return b"\x0a" + varint(len(raw)) + raw


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


def decode_message(data: bytes, fields: list[dict[str, Any]], schemas: dict) -> dict:
    """Decode a protobuf message against its indexed field list."""
    by_number = {int(field["number"]): field for field in fields}
    value: dict[str, Any] = {}
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        number, wire = key >> 3, key & 7
        field = by_number.get(number)
        if field is None:
            raise AssertionError(f"response carried unindexed field number {number}")
        if wire == 0:
            raw, offset = read_varint(data, offset)
            decoded: Any = bool(raw) if field["type"] == "bool" else raw
        elif wire == 2:
            length, offset = read_varint(data, offset)
            chunk = data[offset : offset + length]
            offset += length
            if len(chunk) != length:
                raise AssertionError("truncated protobuf field")
            if field["type"] in schemas:
                decoded = decode_message(chunk, schemas[field["type"]], schemas)
            elif field["type"] == "bytes":
                decoded = chunk.hex()
            else:
                decoded = chunk.decode(errors="replace")
        else:
            raise AssertionError(f"unsupported response wire type {wire}")
        if field.get("repeated"):
            value.setdefault(field["name"], []).append(decoded)
        else:
            value[field["name"]] = decoded
    return value


def is_default(value: Any) -> bool:
    """Return whether a decoded value is the proto3 default for its type."""
    return value is None or value == "" or value == 0 or value == [] or value is False


def cover(
    json_items: list[dict[str, Any]],
    proto_items: list[dict[str, Any]],
    fields: list[dict[str, Any]],
    path: str,
    spec: dict[str, Any],
    schemas: dict[str, list[dict[str, Any]]],
    problems: list[str],
    coverage: dict[str, Any],
) -> None:
    """Assert both representations cover every indexed field at one path."""
    names = [field["name"] for field in fields]
    for item in json_items:
        missing = sorted(set(names) - set(item))
        if missing:
            problems.append(f"{path}: JSON omitted {missing}")
    present = {name for item in proto_items for name in item}
    coverage[path] = {
        "indexed": sorted(names),
        "json_elements": len(json_items),
        "json_present": sorted({name for item in json_items for name in item}),
        "protobuf_elements": len(proto_items),
        "protobuf_present": sorted(present),
    }
    # proto3 omits a default-valued scalar, so a field absent from the wire is
    # only acceptable when the JSON view shows it default in every element.
    default_everywhere = {
        name
        for name in names
        if json_items and all(is_default(item.get(name)) for item in json_items)
    }
    absent = sorted(set(names) - present - default_everywhere)
    if absent:
        problems.append(f"{path}: protobuf omitted non-default {absent}")
    for field in fields:
        if field["type"] not in schemas:
            continue
        name = field["name"]
        nested_spec = spec.get(name, {}) if isinstance(spec, dict) else {}
        json_children = [
            child for item in json_items for child in (item.get(name) or [])
        ]
        proto_children = [
            child for item in proto_items for child in (item.get(name) or [])
        ]
        minimum = int(nested_spec.get("min", 0))
        if len(json_children) < minimum or len(proto_children) < minimum:
            problems.append(
                f"{path}.{name}: expected at least {minimum} element(s), observed "
                f"{len(json_children)} over JSON and {len(proto_children)} over "
                "protobuf"
            )
        cover(
            json_children,
            proto_children,
            schemas[field["type"]],
            f"{path}.{name}",
            nested_spec.get("nested", {}),
            schemas,
            problems,
            coverage,
        )


def identity(value: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    """Project a response onto the parts that must not change between calls."""
    projection: dict[str, Any] = {}
    for name in spec.get("stable", []):
        item = value.get(name)
        projection[name] = sorted(item) if isinstance(item, list) else item
    for name, rules in spec.get("repeated", {}).items():
        rows = []
        for item in value.get(name) or []:
            row = {key: item.get(key) for key in rules["identity"]}
            for nested_name, nested_rules in (rules.get("nested") or {}).items():
                row[nested_name] = sorted(
                    json.dumps(
                        {key: child.get(key) for key in nested_rules["identity"]},
                        sort_keys=True,
                    )
                    for child in (item.get(nested_name) or [])
                )
            rows.append(json.dumps(row, sort_keys=True))
        # Interface and disk ordering is not part of the contract and does vary
        # between calls, so compare the set of objects rather than the list.
        projection[name] = sorted(rows)
    return projection


def monotonic_problems(
    first: dict[str, Any], second: dict[str, Any], spec: dict[str, Any]
) -> list[str]:
    """Return counters that moved backwards between two observations."""
    problems = []
    for name in spec.get("monotonic", []):
        if int(second.get(name, 0)) < int(first.get(name, 0)):
            problems.append(f"{name} decreased between identical calls")
    for name, rules in spec.get("repeated", {}).items():
        counters = rules.get("monotonic") or []
        if not counters:
            continue
        keyed = {
            tuple(item.get(key) for key in rules["identity"]): item
            for item in second.get(name) or []
        }
        for item in first.get(name) or []:
            later = keyed.get(tuple(item.get(key) for key in rules["identity"]))
            if later is None:
                continue
            for counter in counters:
                if int(later.get(counter, 0)) < int(item.get(counter, 0)):
                    problems.append(f"{name}.{counter} decreased between calls")
    return problems


def structural_summary(value: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    """Summarise a response without persisting guest network or disk content."""
    summary: dict[str, Any] = {}
    for name, item in value.items():
        if isinstance(item, list):
            summary[name] = {"type": "array", "length": len(item)}
        elif isinstance(item, str):
            summary[name] = {
                "type": "string",
                "length": len(item),
                "sha256": hashlib.sha256(item.encode()).hexdigest(),
            }
        else:
            summary[name] = {"type": type(item).__name__, "value": item}
    for name in spec.get("repeated", {}):
        summary[name]["element_field_sets"] = sorted(
            {json.dumps(sorted(item), sort_keys=True) for item in value.get(name) or []}
        )
    return summary


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


def run_cli(argv: list[str]) -> tuple[int, str]:
    """Run a lease-owned VMM CLI command."""
    process = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False
    )
    return process.returncode, process.stdout.decode(errors="replace")


def inventory(root: pathlib.Path, method: str) -> tuple[list, dict]:
    """Return the indexed response fields and guest message schemas."""
    document = json.loads((root / "api-inventory.json").read_text())
    component = document["components"]["guest-os"]
    matches = [
        entry
        for entry in component["rpc_methods"]
        if entry.get("service") == "ProxiedGuestApi" and entry.get("method") == method
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one inventory entry for {method}")
    schemas = {
        schema["name"]: schema["fields"]
        for schema in component["message_schemas"]
        if schema.get("name")
    }
    return matches[0]["response_fields"], schemas


def main() -> int:
    """Run one read-only ProxiedGuestApi regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    spec = CASES[case_id]
    method = spec["method"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    steps: list[dict[str, str]] = []
    failures: list[str] = []
    evidence: dict[str, Any] = {
        "case_id": case_id,
        "environment": "HARDWARE",
        "service": "ProxiedGuestApi",
        "method": method,
    }
    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        values = manifest["values"]
        service = values["services"]["ProxiedGuestApi"]
        vm_id = str(service["id"])
        url = str(service["url"]).format(method=method)
        if not vm_id or not url.startswith("http://127.0.0.1:"):
            raise AssertionError(
                "fixture did not provide an isolated ProxiedGuestApi target"
            )
        info_code, info_text = run_cli([str(item) for item in values["vm_info_argv"]])
        if info_code != 0:
            raise AssertionError("the lease-owned VMM did not report VM state")
        vm_info = json.loads(info_text)
        if vm_info.get("status") != "running" or vm_info.get("boot_progress") != "done":
            raise AssertionError(f"lease guest is not ready: {vm_info.get('status')}")
        identity_url = str(service["url"]).format(method="Info")
        identity_code, identity_body = request(
            identity_url,
            "application/json",
            json.dumps({"id": vm_id}, separators=(",", ":")).encode(),
        )
        if identity_code != 200:
            raise AssertionError(f"ProxiedGuestApi.Info returned {identity_code}")
        observed_instance = str(json.loads(identity_body).get("instance_id", ""))
        if observed_instance.lower() != str(values["instance_id"]).lower():
            raise AssertionError("the run-scoped VM id resolved to another guest")
        response_fields, schemas = inventory(plan_root, method)
        evidence["prerequisite"] = {
            "profile": manifest["profile"],
            "lease_id": manifest["lease_id"],
            "status": vm_info.get("status"),
            "boot_progress": vm_info.get("boot_progress"),
            "instance_id_matches_lease": True,
            "indexed_response_fields": [field["name"] for field in response_fields],
            "read_only_method_creates_no_object": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The lease-owned VMM reported the intended guest running "
                "with boot progress done, the ProxiedGuestApi listener resolved the "
                "run-scoped VM id to that guest's instance id, and the indexed "
                f"{method} contract was available.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-01 - Proves the isolated VMM listener, the "
            "run-scoped guest identity and the indexed contract were ready.",
            flush=True,
        )
        print(json.dumps(evidence["prerequisite"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        payload = json.dumps({"id": vm_id}, separators=(",", ":")).encode()
        json_code, json_body = request(url, "application/json", payload)
        if json_code != 200:
            raise AssertionError(f"valid JSON {method} returned HTTP {json_code}")
        json_value = json.loads(json_body)
        proto_code, proto_body = request(
            url, "application/octet-stream", encode_id(vm_id)
        )
        if proto_code != 200:
            raise AssertionError(f"valid protobuf {method} returned {proto_code}")
        proto_value = decode_message(proto_body, response_fields, schemas)
        problems: list[str] = []
        coverage: dict[str, Any] = {}
        cover(
            [json_value],
            [proto_value],
            response_fields,
            method,
            spec.get("repeated", {}),
            schemas,
            problems,
            coverage,
        )
        for name in spec["nonempty_strings"]:
            if not str(json_value.get(name, "")):
                problems.append(f"{name} was empty")
        for name in spec["positive"]:
            if int(json_value.get(name, 0)) <= 0:
                problems.append(f"{name} was not positive")
        # Record the observed structure before asserting on it: a mismatch is
        # otherwise only reproducible by leasing another guest.
        evidence["contract"] = {
            "json_http": json_code,
            "json_fields": structural_summary(json_value, spec),
            "protobuf_http": proto_code,
            "protobuf_bytes": len(proto_body),
            "recursive_field_coverage": coverage,
            "problems": problems,
            "sensitive_values_persisted": False,
        }
        if problems:
            raise AssertionError("; ".join(problems))
        unknown_key = f"unknown_{manifest['lease_id']}"
        unknown_code, unknown_body = request(
            url,
            "application/json",
            json.dumps({"id": vm_id, unknown_key: 1}).encode(),
        )
        if unknown_code != 200 or set(json.loads(unknown_body)) != set(json_value):
            raise AssertionError("an unknown JSON member changed the response schema")
        rejections: dict[str, Any] = {}
        for name, content_type, body in (
            ("absent_id", "application/json", b"{}"),
            ("empty_id", "application/json", b'{"id":""}'),
            ("unknown_id", "application/json", f'{{"id":"{UNKNOWN_VM_ID}"}}'.encode()),
            ("schema_invalid_id", "application/json", b'{"id":123}'),
            ("malformed_json", "application/json", b'{"id":'),
            ("malformed_protobuf", "application/octet-stream", b"\x0a\xff"),
        ):
            code, body_out = request(url, content_type, body)
            if code < 400:
                raise AssertionError(f"{name} was accepted with HTTP {code}")
            rejections[name] = {"http": code, "error": structured_error(body_out)}
        evidence["contract"]["unknown_member_http"] = unknown_code
        evidence["contract"]["rejections"] = rejections
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Valid JSON and binary protobuf calls returned every "
                "indexed top-level and nested response field; an unknown member was "
                "ignored, and absent, empty, unresolvable, wrong-typed and malformed "
                "requests returned structured errors in both representations.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-02 - Proves recursive JSON/protobuf field "
            "coverage and structured rejection of invalid input.",
            flush=True,
        )
        print(
            json.dumps(
                {"json_http": json_code, "protobuf_http": proto_code, **rejections},
                sort_keys=True,
            ),
            flush=True,
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)

        print(f"STEP {case_id}-step-03 START", flush=True)
        repeat_code, repeat_body = request(url, "application/json", payload)
        if repeat_code != 200:
            raise AssertionError(f"{method} was unavailable after invalid input")
        repeat_value = json.loads(repeat_body)
        first_identity = identity(json_value, spec)
        repeat_identity = identity(repeat_value, spec)
        changed_identity_fields = sorted(
            name
            for name in set(first_identity) | set(repeat_identity)
            if first_identity.get(name) != repeat_identity.get(name)
        )
        drift = []
        if changed_identity_fields:
            drift.append("the identity of the returned objects changed between calls")
        drift.extend(monotonic_problems(json_value, repeat_value, spec))
        evidence["repeat"] = {
            "http": repeat_code,
            "byte_stable": repeat_body == json_body,
            "changed_identity_fields": changed_identity_fields,
            "first_identity_sha256": hashlib.sha256(
                json.dumps(first_identity, sort_keys=True).encode()
            ).hexdigest(),
            "repeat_identity_sha256": hashlib.sha256(
                json.dumps(repeat_identity, sort_keys=True).encode()
            ).hexdigest(),
            "drift": drift,
            "sensitive_values_persisted": False,
        }
        if drift:
            raise AssertionError("; ".join(drift))
        state_code, state_text = run_cli([str(item) for item in values["vm_info_argv"]])
        state = json.loads(state_text) if state_code == 0 else {}
        if state.get("status") != "running":
            raise AssertionError("the lease guest did not remain running")
        log_code, log_text = run_cli(
            [
                *[str(item) for item in values["vmm_cli_argv"]],
                "logs",
                "-n",
                "200",
                vm_id,
            ]
        )
        log_lines = log_text.splitlines()[-200:]
        evidence["repeat"].update(
            {
                "object_identity_stable": True,
                "counters_monotonic": True,
                "first_sha256": hashlib.sha256(json_body).hexdigest(),
                "repeat_sha256": hashlib.sha256(repeat_body).hexdigest(),
                "post_negative_status": state.get("status"),
            }
        )
        evidence["diagnostics"] = {
            "source": "lease-owned VMM guest log",
            "exit_code": log_code,
            "observed_lines": len(log_lines),
            "panic_lines": sum(1 for line in log_lines if "panic" in line.lower()),
            "sha256": hashlib.sha256("\n".join(log_lines).encode()).hexdigest(),
            "content_persisted": False,
        }
        if evidence["diagnostics"]["panic_lines"]:
            raise AssertionError("the lease guest log recorded a panic")
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "A post-rejection call succeeded, the returned object "
                "identity was unchanged and live counters were monotonic, the guest "
                "remained running and scoped to the lease, and bounded guest "
                "diagnostics recorded no panic.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-03 - Proves post-error availability, the "
            "documented repeat semantics and bounded diagnostics.",
            flush=True,
        )
        print(json.dumps(evidence["repeat"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as error:
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
        "name": f"ProxiedGuestApi.{method} contract matrix",
        "path": "artifacts/proxiedguestapi-read-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Recursive JSON and protobuf field coverage, structured "
        "rejection statuses, repeat identity and counter monotonicity, and bounded "
        "guest diagnostics. Guest network, disk and container content is summarised "
        "by length and hash rather than persisted.",
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
            "summary": f"ProxiedGuestApi.{method} returned every indexed response "
            "field over JSON and binary protobuf for the lease-owned guest, rejected "
            "invalid input with structured errors, and repeated calls matched the "
            "method's live-state semantics."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": f"{method} is read-only, so the case creates and removes no "
            "run-scoped object. The response carries live guest state, so the repeat "
            "assertion compares object identity and counter monotonicity rather than "
            "byte equality.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
