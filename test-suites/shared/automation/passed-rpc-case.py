#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for previously confirmed simulator RPC cases."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

CASES = {
    "tc-gos-tappd-001": (
        "Tappd",
        "DeriveKey",
        {
            "path": "regression/a",
            "subject": "localhost",
            "alt_names": ["localhost"],
            "usage_ra_tls": True,
            "usage_server_auth": True,
            "usage_client_auth": False,
            "random_seed": False,
        },
        False,
    ),
    "tc-gos-tappd-002": (
        "Tappd",
        "DeriveK256Key",
        {"path": "regression/a", "purpose": "regression", "algorithm": "k256"},
        True,
    ),
    "tc-gos-tappd-004": ("Tappd", "RawQuote", {"report_data": "11" * 64}, True),
    "tc-gos-tappd-006": ("Tappd", "Version", {}, True),
    "tc-gos-dstackguest-001": (
        "DstackGuest",
        "GetTlsKey",
        {
            "subject": "localhost",
            "alt_names": ["localhost"],
            "usage_ra_tls": True,
            "usage_server_auth": True,
            "usage_client_auth": False,
            "not_before": 0,
            "not_after": 4102444800,
            "with_app_info": True,
        },
        False,
    ),
    "tc-gos-dstackguest-002": (
        "DstackGuest",
        "GetKey",
        {"path": "regression/a", "purpose": "regression", "algorithm": "ed25519"},
        True,
    ),
    "tc-gos-dstackguest-003": (
        "DstackGuest",
        "GetQuote",
        {"report_data": "22" * 64},
        True,
    ),
    "tc-gos-dstackguest-004": (
        "DstackGuest",
        "Attest",
        {"report_data": "33" * 64},
        True,
    ),
    "tc-gos-dstackguest-005": ("DstackGuest", "Info", {}, True),
    "tc-gos-dstackguest-007": (
        "DstackGuest",
        "Sign",
        {"algorithm": "ed25519", "data": "44" * 32},
        True,
    ),
    "tc-gos-dstackguest-009": ("DstackGuest", "Version", {}, True),
    "tc-gos-worker-001": ("Worker", "Info", {}, True),
    "tc-gos-worker-002": ("Worker", "Version", {}, True),
    "tc-gos-worker-003": (
        "Worker",
        "GetAttestationForAppKey",
        {"algorithm": "ed25519"},
        True,
    ),
    "tc-gos-guestapi-001": ("GuestApi", "Info", {}, True),
    "tc-gos-guestapi-002": ("GuestApi", "SysInfo", {}, False),
    "tc-gos-tappd-003": (
        "Tappd",
        "TdxQuote",
        {
            "report_data": "55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555"
        },
        True,
    ),
    "tc-gos-tappd-005": ("Tappd", "Info", {}, True),
    "tc-gos-guestapi-003": ("GuestApi", "NetworkInfo", {}, False),
    "tc-gos-guestapi-004": ("GuestApi", "ListContainers", {}, False),
    "tc-gos-guestapi-005": ("GuestApi", "Shutdown", {}, False),
    # The no-GPU answer is constant, but a host with an NVIDIA display device
    # makes the simulator report a timestamped sampling failure instead, so
    # stability is asserted by the GpuInfo contract check rather than here.
    "tc-gos-guestapi-006": ("GuestApi", "GpuInfo", {}, False),
}

# OID of the RA-TLS extension that carries the versioned attestation.
RATLS_ATTESTATION_OID = "1.3.6.1.4.1.62397.1.8"
# The last timestamp an RFC 5280 certificate can carry.
MAX_CERT_VALIDITY_SECS = 253_402_300_799
NVIDIA_VENDOR_ID = "0x10de"
DISPLAY_CLASS_PREFIXES = ("0x0300", "0x0302")


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


def varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def scalar_bytes(field: dict[str, Any], value: Any) -> tuple[int, bytes]:
    """Encode a scalar field value."""
    kind = field["type"]
    if kind in ("string", "bytes"):
        if kind == "bytes":
            raw = bytes.fromhex(str(value))
        else:
            raw = str(value).encode()
        return 2, varint(len(raw)) + raw
    if kind == "bool":
        return 0, varint(1 if value else 0)
    if kind.startswith(("uint", "int", "sint", "fixed", "sfixed")):
        return 0, varint(int(value))
    raise ValueError(f"unsupported request field type: {kind}")


def encode_request(fields: list[dict[str, Any]], payload: dict[str, Any]) -> bytes:
    """Encode a protobuf request body."""
    output = bytearray()
    for field in fields:
        if field["name"] not in payload:
            continue
        values = (
            payload[field["name"]]
            if field.get("repeated")
            else [payload[field["name"]]]
        )
        for value in values:
            wire, encoded = scalar_bytes(field, value)
            output.extend(varint((int(field["number"]) << 3) | wire))
            output.extend(encoded)
    return bytes(output)


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


def decode_wire(data: bytes) -> dict[int, list[tuple[int, bytes | int]]]:
    """Decode protobuf wire fields."""
    values: dict[int, list[tuple[int, bytes | int]]] = {}
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 2:
            length, offset = read_varint(data, offset)
            value = data[offset : offset + length]
            offset += length
        else:
            raise ValueError(f"unsupported response wire type {wire}")
        values.setdefault(number, []).append((wire, value))
    return values


def call(socket: str, route: str, content_type: str, body: bytes) -> tuple[int, bytes]:
    """Call a unix-socket HTTP endpoint."""
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


def msgpack_decode(data: bytes, offset: int = 0) -> tuple[Any, int]:
    """Decode one MessagePack value, enough for rmp_serde attestation maps."""
    tag = data[offset]
    offset += 1

    def take(count: int) -> bytes:
        nonlocal offset
        if offset + count > len(data):
            raise ValueError("truncated MessagePack value")
        chunk = data[offset : offset + count]
        offset += count
        return chunk

    def number(count: int, signed: bool = False) -> int:
        return int.from_bytes(take(count), "big", signed=signed)

    def items(count: int) -> list[Any]:
        nonlocal offset
        values = []
        for _ in range(count):
            value, offset = msgpack_decode(data, offset)
            values.append(value)
        return values

    def mapping(count: int) -> dict[Any, Any]:
        flat = items(count * 2)
        return dict(zip(flat[0::2], flat[1::2]))

    if tag <= 0x7F:
        return tag, offset
    if 0x80 <= tag <= 0x8F:
        return mapping(tag & 0x0F), offset
    if 0x90 <= tag <= 0x9F:
        return items(tag & 0x0F), offset
    if 0xA0 <= tag <= 0xBF:
        return take(tag & 0x1F).decode(), offset
    if tag >= 0xE0:
        return tag - 0x100, offset
    simple = {0xC0: None, 0xC2: False, 0xC3: True}
    if tag in simple:
        return simple[tag], offset
    if tag in (0xC4, 0xC5, 0xC6):
        return take(number(1 << (tag - 0xC4))), offset
    if tag in (0xCC, 0xCD, 0xCE, 0xCF):
        return number(1 << (tag - 0xCC)), offset
    if tag in (0xD0, 0xD1, 0xD2, 0xD3):
        return number(1 << (tag - 0xD0), signed=True), offset
    if tag in (0xD9, 0xDA, 0xDB):
        return take(number(1 << (tag - 0xD9))).decode(), offset
    if tag in (0xDC, 0xDD):
        return items(number(2 << (tag - 0xDC))), offset
    if tag in (0xDE, 0xDF):
        return mapping(number(2 << (tag - 0xDE))), offset
    raise ValueError(f"unsupported MessagePack tag 0x{tag:02x}")


def as_bytes(value: Any) -> bytes:
    """Normalise an rmp_serde byte vector (bin or integer array) to bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, list) and all(isinstance(item, int) for item in value):
        return bytes(value)
    raise AssertionError("attestation byte field was neither bin nor integer array")


def msgpack_v1_attestation(raw: bytes) -> dict[str, Any]:
    """Require the v1 wire form: a MessagePack map carrying the V1 schema."""
    if not raw or not (0x80 <= raw[0] <= 0x8F or raw[0] in (0xDE, 0xDF)):
        prefix = f"0x{raw[0]:02x}" if raw else "empty"
        raise AssertionError(
            f"v1 attestation is not a MessagePack map (first byte {prefix})"
        )
    value, consumed = msgpack_decode(raw)
    if consumed != len(raw):
        raise AssertionError("v1 attestation carries trailing bytes after the map")
    if not isinstance(value, dict) or not {"version", "platform", "stack"} <= set(
        value
    ):
        raise AssertionError("v1 attestation map lacks version/platform/stack")
    stack = value["stack"]
    if not isinstance(stack, dict) or not isinstance(stack.get("data"), dict):
        raise AssertionError("v1 attestation stack evidence is malformed")
    return value


def json_hex_field(body: bytes, name: str) -> bytes:
    """Read one hex-encoded bytes field from a pRPC JSON response."""
    value = json.loads(body).get(name)
    if not isinstance(value, str):
        raise AssertionError(f"response field {name} was not hex text")
    return bytes.fromhex(value)


def v1_route(route: str, method: str) -> str:
    """Map a resolved frozen DstackGuest route onto the dstack.guest.v1 mount."""
    base, separator, _ = route.rpartition("/")
    if not separator:
        raise AssertionError(f"unexpected DstackGuest route {route}")
    return f"{base}/v1/{method}"


def check_attest_wire(
    socket: str, route: str, payload: dict[str, Any], **_: Any
) -> dict[str, Any]:
    """PR #1207: v0 Attest stays legacy SCALE while v1 Attest is always MessagePack."""
    legacy_code, legacy_body = call(
        socket, route, "application/json", json.dumps(payload).encode()
    )
    if legacy_code != 200:
        raise AssertionError(f"v0 Attest returned HTTP {legacy_code}")
    legacy = json_hex_field(legacy_body, "attestation")
    if not legacy or legacy[0] != 0x00:
        raise AssertionError(
            "v0 Attest no longer returns the legacy SCALE form for a legacy platform"
        )
    v1_code, v1_body = call(
        socket,
        v1_route(route, "Attest"),
        "application/json",
        json.dumps(payload).encode(),
    )
    if v1_code != 200:
        raise AssertionError(f"v1 Attest returned HTTP {v1_code}")
    attestation = msgpack_v1_attestation(json_hex_field(v1_body, "attestation"))
    report_data = as_bytes(attestation["stack"]["data"].get("report_data"))
    if report_data != bytes.fromhex(payload["report_data"]):
        raise AssertionError(
            "v1 Attest MessagePack report_data does not match the request"
        )
    return {
        "v0_first_byte": "0x00",
        "v1_first_byte": f"0x{json_hex_field(v1_body, 'attestation')[0]:02x}",
        "v1_version": attestation["version"],
        "v1_platform_kind": attestation["platform"].get("kind")
        if isinstance(attestation["platform"], dict)
        else None,
        "v1_report_data_bound": True,
    }


def certificate_attestation(chain: list[Any]) -> bytes:
    """Extract the RA-TLS attestation bytes from the leaf certificate."""
    from cryptography import x509

    if not chain or not isinstance(chain[0], str):
        raise AssertionError("certificate chain is empty")
    leaf = x509.load_pem_x509_certificate(chain[0].encode())
    for extension in leaf.extensions:
        if extension.oid.dotted_string != RATLS_ATTESTATION_OID:
            continue
        der = extension.value.value
        if not der or der[0] != 0x04:
            raise AssertionError(
                "RA-TLS attestation extension is not a DER OCTET STRING"
            )
        length, offset = der[1], 2
        if length & 0x80:
            width = length & 0x7F
            length = int.from_bytes(der[2 : 2 + width], "big")
            offset = 2 + width
        content = der[offset : offset + length]
        if len(content) != length or offset + length != len(der):
            raise AssertionError("RA-TLS attestation extension length is inconsistent")
        return content
    raise AssertionError("RA-TLS certificate omitted the attestation extension")


def check_certificate_attestation_wire(
    socket: str,
    route: str,
    payload: dict[str, Any],
    json_value: dict[str, Any],
    **_: Any,
) -> dict[str, Any]:
    """PR #1207: GetTlsKey embeds legacy SCALE; v1 IssueCert embeds MessagePack V1."""
    legacy = certificate_attestation(json_value.get("certificate_chain", []))
    if not legacy or legacy[0] != 0x00:
        raise AssertionError(
            "v0 GetTlsKey certificate no longer embeds the legacy SCALE attestation"
        )
    request = {
        "subject": payload["subject"],
        "alt_names": payload["alt_names"],
        "usage_ra_tls": True,
        "usage_server_auth": payload["usage_server_auth"],
        "usage_client_auth": payload["usage_client_auth"],
    }
    code, body = call(
        socket,
        v1_route(route, "IssueCert"),
        "application/json",
        json.dumps(request).encode(),
    )
    if code != 200:
        raise AssertionError(f"v1 IssueCert returned HTTP {code}")
    embedded = certificate_attestation(json.loads(body).get("certificate_chain", []))
    attestation = msgpack_v1_attestation(embedded)
    return {
        "v0_certificate_first_byte": "0x00",
        "v1_certificate_first_byte": f"0x{embedded[0]:02x}",
        "v1_certificate_version": attestation["version"],
        "private_key_persisted": False,
    }


def check_certificate_validity_bounds(
    socket: str, route: str, payload: dict[str, Any], **_: Any
) -> dict[str, Any]:
    """PR #1232: a validity bound past 9999-12-31T23:59:59Z is refused, not signed."""
    from cryptography import x509

    observed: dict[str, Any] = {}
    for surface, target in (("v0", route), ("v1", v1_route(route, "IssueCert"))):
        request = {key: value for key, value in payload.items() if key != "not_before"}
        request["not_after"] = MAX_CERT_VALIDITY_SECS
        code, body = call(
            socket, target, "application/json", json.dumps(request).encode()
        )
        if code != 200:
            raise AssertionError(
                f"{surface} last representable not_after returned HTTP {code}"
            )
        leaf = x509.load_pem_x509_certificate(
            json.loads(body)["certificate_chain"][0].encode()
        )
        # cryptography < 42 has only the naive UTC accessor.
        not_after = getattr(leaf, "not_valid_after_utc", None) or (
            leaf.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        )
        if int(not_after.timestamp()) != MAX_CERT_VALIDITY_SECS:
            raise AssertionError(
                f"{surface} certificate notAfter was not 9999-12-31T23:59:59Z"
            )
        rejected = {}
        for field, value in (
            ("not_after", MAX_CERT_VALIDITY_SECS + 1),
            ("not_after", 2**64 - 1),
            ("not_before", MAX_CERT_VALIDITY_SECS + 1),
        ):
            bad = {**request, field: value}
            if field == "not_before":
                bad.pop("not_after")
            code, body = call(
                socket, target, "application/json", json.dumps(bad).encode()
            )
            error = json.loads(body).get("error") if body else None
            if code < 400 or not isinstance(error, str) or field not in error:
                raise AssertionError(
                    f"{surface} unrepresentable {field}={value} was not refused by name"
                )
            rejected[f"{field}={value}"] = code
        code, _ = call(socket, route, "application/json", json.dumps(payload).encode())
        if code != 200:
            raise AssertionError(
                f"GetTlsKey was unavailable after the {surface} refusals"
            )
        observed[surface] = {"maximum_accepted": True, "rejected_http": rejected}
    return observed


def check_tls_key(**kwargs: Any) -> dict[str, Any]:
    """Run every post-baseline GetTlsKey check."""
    return {
        **check_certificate_attestation_wire(**kwargs),
        "validity_bounds": check_certificate_validity_bounds(**kwargs),
    }


def json_call(socket: str, route: str) -> dict[str, Any]:
    """Call one Empty-input route and require a JSON object."""
    code, body = call(socket, route, "application/json", b"{}")
    value = json.loads(body) if code == 200 else None
    if not isinstance(value, dict):
        raise AssertionError(f"{route} returned HTTP {code}")
    return value


def check_private_tcbinfo_info(
    socket: str, route: str, json_value: dict[str, Any], **_: Any
) -> dict[str, Any]:
    """PR #1263: with public_tcbinfo off, both Info surfaces answer from the identity cache."""
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    helpers = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"]) / "shared/automation"
    public_v1 = json_call(socket, route.replace("/prpc/Info", "/prpc/v1/Info"))
    for name in ("app_compose", "vm_config", "key_provider_info"):
        if not public_v1.get(name):
            raise AssertionError(f"public v1 Info omitted {name}")
    identity = ("app_id", "instance_id", "device_id", "mr_aggregated", "os_image_hash")
    identity += ("compose_hash", "app_name")
    with tempfile.TemporaryDirectory(prefix="dstack-private-tcbinfo-") as directory:
        work = pathlib.Path(directory)
        fixtures = work / "fixtures"
        fixtures.mkdir()
        for name in (
            "appkeys.json",
            "attestation.bin",
            "sys-config.json",
            "dstack.toml",
        ):
            (fixtures / name).write_bytes(
                (pathlib.Path(runtime["simulator_fixtures"]) / name).read_bytes()
            )
        compose = json.loads(
            (
                pathlib.Path(runtime["simulator_fixtures"]) / "app-compose.json"
            ).read_text()
        )
        compose["public_tcbinfo"] = False
        (fixtures / "app-compose.json").write_text(json.dumps(compose))
        manifest = work / "runtime-manifest.json"
        manifest.write_text(
            json.dumps({**runtime, "simulator_fixtures": str(fixtures)})
        )
        simulator = pathlib.Path(
            tempfile.mkdtemp(prefix="dstack-test-case-", dir="/tmp")
        )
        fixture = work / "simulator-fixture.json"
        started = subprocess.run(
            [
                str(helpers / "start-simulator.sh"),
                str(manifest),
                str(simulator),
                str(fixture),
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        try:
            if started.returncode:
                raise AssertionError(
                    f"private-tcbinfo simulator failed to start: {started.stderr[-500:]}"
                )
            private_socket = json.loads(fixture.read_text())["services"]["Worker"][
                "socket"
            ]
            frozen = [json_call(private_socket, route) for _ in range(3)]
            v1 = json_call(private_socket, "/prpc/v1/Info")
        finally:
            if fixture.is_file():
                subprocess.run(
                    [str(helpers / "stop-simulator.sh"), str(fixture)],
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
            else:
                simulator.rmdir()
    for value in frozen:
        if value.get("tcb_info") != "" or value.get("vm_config") != "":
            raise AssertionError(
                "frozen Info served tcb_info or vm_config while private"
            )
        if value.get("key_provider_info") != json_value.get("key_provider_info"):
            raise AssertionError("frozen Info stopped serving key_provider_info")
        changed = [name for name in identity if value.get(name) != json_value.get(name)]
        if changed:
            raise AssertionError(f"frozen private Info identity differed: {changed}")
    for name in ("app_compose", "vm_config", "key_provider_info"):
        if v1.get(name) != "":
            raise AssertionError(f"v1 Info served {name} while private")
    changed = [name for name in identity if v1.get(name) != public_v1.get(name)]
    if changed:
        raise AssertionError(f"v1 private Info identity differed: {changed}")
    return {
        "frozen_calls": len(frozen),
        "frozen_hidden": ["tcb_info", "vm_config"],
        "v1_hidden": ["app_compose", "vm_config", "key_provider_info"],
        "identity_fields_equal": list(identity),
    }


def host_nvidia_display_devices() -> int:
    """Count NVIDIA display-class PCI devices the way lspci::sysfs does."""
    count = 0
    for device in pathlib.Path("/sys/bus/pci/devices").glob("*"):
        try:
            klass = (device / "class").read_text().strip()
            vendor = (device / "vendor").read_text().strip()
        except OSError:
            continue
        if klass[:6] in DISPLAY_CLASS_PREFIXES and vendor == NVIDIA_VENDOR_ID:
            count += 1
    return count


def check_gpu_info_contract(
    socket: str,
    route: str,
    json_value: dict[str, Any],
    json_body: bytes,
    protobuf_body: bytes,
    **_: Any,
) -> dict[str, Any]:
    """GuestApi.GpuInfo: the documented no-GPU and unavailable response shapes."""
    nvidia = host_nvidia_display_devices()
    gpus = json_value.get("gpus")
    error = json_value.get("error")
    if not isinstance(gpus, list) or not isinstance(error, str):
        raise AssertionError("GpuInfo gpus/error have the wrong JSON types")
    for name in ("cc_ready", "cc_enabled", "sample_age_ms"):
        if name not in json_value:
            raise AssertionError(f"GpuInfo JSON omitted optional field {name}")
    if nvidia == 0:
        # PCI gate: no NVIDIA device means the collector never runs and the
        # answer is "ran, found nothing" -- empty devices, empty error, and no
        # CC state or sample age at all.
        expected = {
            "gpus": [],
            "error": "",
            "cc_ready": None,
            "cc_enabled": None,
            "sample_age_ms": None,
        }
        if json_value != expected:
            raise AssertionError(f"no-GPU GpuInfo response was {json_value}")
        if protobuf_body != b"":
            raise AssertionError(
                "no-GPU GpuInfo protobuf encoded unset optional fields"
            )
        repeat_code, repeat_body = call(socket, route, "application/json", b"{}")
        if repeat_code != 200 or repeat_body != json_body:
            raise AssertionError("no-GPU GpuInfo response was not stable")
        shape = "no-gpu"
    else:
        # The simulator host has an NVIDIA card but no in-guest collector, so
        # the only valid answers are "unavailable" or a real sample.
        if error:
            if (
                gpus
                or json_value["cc_ready"] is not None
                or json_value["cc_enabled"] is not None
            ):
                raise AssertionError(
                    "unavailable GpuInfo response carried devices or CC state"
                )
            shape = "unavailable"
        else:
            if json_value["sample_age_ms"] is None:
                raise AssertionError("sampled GpuInfo response omitted sample_age_ms")
            shape = "sampled"
    return {
        "host_nvidia_display_devices": nvidia,
        "shape": shape,
        "gpu_count": len(gpus),
        "error_present": bool(error),
        "protobuf_bytes": len(protobuf_body),
    }


EXTRA_CHECKS = {
    "tc-gos-dstackguest-001": check_tls_key,
    "tc-gos-dstackguest-004": check_attest_wire,
    "tc-gos-guestapi-006": check_gpu_info_contract,
    "tc-gos-worker-001": check_private_tcbinfo_info,
}


def inventory_entry(root: pathlib.Path, service: str, method: str) -> dict[str, Any]:
    """Load the API inventory entry."""
    document = json.loads((root / "catalog" / "api-inventory.json").read_text())
    matches = []

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


def structural_json(value: dict[str, Any]) -> dict[str, Any]:
    """Build a structural JSON summary."""
    output = {}
    for key, item in value.items():
        if isinstance(item, list):
            output[key] = {
                "type": "array",
                "length": len(item),
                "item_lengths": [len(str(v)) for v in item],
            }
        elif isinstance(item, str):
            output[key] = {
                "type": "string",
                "length": len(item),
                "sha256": hashlib.sha256(item.encode()).hexdigest(),
            }
        else:
            output[key] = {"type": type(item).__name__, "value": item}
    return output


def main() -> int:
    """Run the case harness."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    service, method, payload, deterministic = CASES[case_id]
    steps = []
    status = "PASS"
    failure = None
    matrix: dict[str, Any] = {
        "case_id": case_id,
        "environment": "SIMULATION",
        "service": service,
        "method": method,
    }
    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        fixture = manifest["values"]
        service_fixture = fixture["services"][service]
        socket = service_fixture["socket"]
        route = service_fixture["route"].replace("<Method>", method)
        if not pathlib.Path(socket).is_socket():
            raise RuntimeError(f"fixture socket is not available: {socket}")
        entry = inventory_entry(plan_root, service, method)
        matrix["fixture"] = {
            "profile": manifest["profile"],
            "lease_id": manifest["lease_id"],
            "socket_available": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The lease-owned simulator socket and indexed RPC contract were available.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-01 - Proves that the isolated simulator listener and indexed method contract were ready.",
            flush=True,
        )
        print(json.dumps(matrix["fixture"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        json_code, json_body = call(
            socket, route, "application/json", json.dumps(payload).encode()
        )
        if json_code != 200:
            raise AssertionError(f"valid JSON request returned HTTP {json_code}")
        expected_names = [field["name"] for field in entry["response_fields"]]
        # Unit/Empty responses have an empty HTTP body. Retain compatibility
        # with JSON null while never accepting an empty body for a response
        # that declares fields.
        if not json_body:
            if expected_names:
                raise AssertionError("non-Empty JSON response had an empty body")
            json_value: dict[str, Any] = {}
        else:
            raw_json_value = json.loads(json_body)
            if raw_json_value is None:
                json_value = {}
            elif isinstance(raw_json_value, dict):
                json_value = raw_json_value
            else:
                raise AssertionError(
                    f"JSON response was not an object or null: {type(raw_json_value).__name__}"
                )
        missing = sorted(set(expected_names) - set(json_value))
        if missing:
            raise AssertionError(f"JSON response omitted fields: {missing}")
        binary_request = encode_request(entry["request_fields"], payload)
        protobuf_code, protobuf_body = call(
            socket, route, "application/octet-stream", binary_request
        )
        if protobuf_code != 200:
            raise AssertionError(
                f"valid protobuf request returned HTTP {protobuf_code}"
            )
        wire = decode_wire(protobuf_body)
        expected_numbers = {
            int(field["number"])
            for field in entry["response_fields"]
            if json_value.get(field["name"]) not in (None, "", 0, False, [])
        }
        if not expected_numbers.issubset(wire):
            raise AssertionError(
                f"protobuf response omitted fields: {sorted(expected_numbers - set(wire))}"
            )
        bad_route_code, bad_route_body = call(
            socket, route + "-invalid", "application/json", b"{}"
        )
        if bad_route_code < 400:
            raise AssertionError("invalid route was accepted")
        try:
            bad_route_value = json.loads(bad_route_body)
        except json.JSONDecodeError as error:
            raise AssertionError(
                "invalid route did not return structured JSON"
            ) from error
        if not isinstance(bad_route_value.get("error"), str):
            raise AssertionError("invalid route response omitted error")
        invalid_code = None
        if entry["request_fields"]:
            first = entry["request_fields"][0]
            wrong = {
                **payload,
                first["name"]: 123 if first["type"] in ("string", "bytes") else "wrong",
            }
            invalid_code, invalid_body = call(
                socket, route, "application/json", json.dumps(wrong).encode()
            )
            if invalid_code < 400:
                raise AssertionError(f"schema-invalid {first['name']} was accepted")
            if not isinstance(json.loads(invalid_body).get("error"), str):
                raise AssertionError("schema-invalid response omitted error")
        extra = EXTRA_CHECKS.get(case_id)
        if extra is not None:
            matrix["post_baseline"] = extra(
                socket=socket,
                route=route,
                payload=payload,
                json_value=json_value,
                json_body=json_body,
                protobuf_body=protobuf_body,
            )
        matrix["contract"] = {
            "json_http": json_code,
            "json_fields": structural_json(json_value),
            "protobuf_http": protobuf_code,
            "protobuf_bytes": len(protobuf_body),
            "protobuf_field_numbers": sorted(wire),
            "invalid_route_http": bad_route_code,
            "invalid_field_http": invalid_code,
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Valid JSON and protobuf requests returned every indexed response field; invalid routing and schema input were rejected.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-02 - Proves JSON/protobuf field coverage and structured rejection of invalid input.",
            flush=True,
        )
        print(
            json.dumps(
                {
                    "json_http": json_code,
                    "json_fields": sorted(json_value),
                    "protobuf_http": protobuf_code,
                    "protobuf_fields": sorted(wire),
                    "invalid_route_http": bad_route_code,
                    "invalid_field_http": invalid_code,
                    "post_baseline": matrix.get("post_baseline"),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)

        print(f"STEP {case_id}-step-03 START", flush=True)
        repeat_code, repeat_body = call(
            socket, route, "application/json", json.dumps(payload).encode()
        )
        if repeat_code != 200:
            raise AssertionError(
                f"post-error valid request returned HTTP {repeat_code}"
            )
        if deterministic and repeat_body != json_body:
            raise AssertionError(
                "documented deterministic response changed across identical requests"
            )
        matrix["repeat"] = {
            "http": repeat_code,
            "exact_match_required": deterministic,
            "exact_match": repeat_body == json_body,
            "first_sha256": hashlib.sha256(json_body).hexdigest(),
            "repeat_sha256": hashlib.sha256(repeat_body).hexdigest(),
            "sensitive_response_persisted": False,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "The service remained available after invalid input and repeated behavior matched the documented determinism policy.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-03 - Proves post-error availability and repeat-call semantics without persisting response secrets.",
            flush=True,
        )
        print(json.dumps(matrix["repeat"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as error:
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        completed = {step["id"] for step in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in completed:
                steps.append({"id": step_id, "status": "FAIL", "observed": failure})
        print(
            f"EVIDENCE {case_id}-step-{len(steps):02d} - Captures the first deterministic harness mismatch.",
            flush=True,
        )
        print(failure, file=sys.stderr, flush=True)

    matrix["status"] = status
    matrix["failure"] = failure
    matrix_path = artifacts / "rpc-regression-matrix.json"
    atomic_json(matrix_path, matrix)
    artifact = {
        "name": "RPC regression matrix",
        "path": "artifacts/rpc-regression-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Records structural JSON/protobuf coverage, invalid-input rejection, repeat semantics, and proves that no native secret response was persisted.",
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Deterministic simulator RPC regression passed."
            if status == "PASS"
            else failure,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "SIMULATION: this confirms RPC behavior, not physical TEE trust properties.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
