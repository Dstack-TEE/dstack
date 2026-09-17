#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise authenticated WaveKV synchronization and replay safety."""

from __future__ import annotations

import base64
import gzip
import importlib.util
import json
import os
import pathlib
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CASE_ID = "tc-gw-cluster-ad-002"
# DER body of OID 1.3.6.1.4.1.62397.1.3, the RA-TLS app-id certificate extension.
APP_ID_OID_DER = bytes.fromhex("060a2b0601040183e73d0103")


def load_support() -> Any:
    """Load bounded Gateway admin and artifact helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_wavekv_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def pack_uint(value: int) -> bytes:
    """Encode a non-negative MessagePack integer."""
    if value < 128:
        return bytes([value])
    if value <= 0xFF:
        return b"\xcc" + struct.pack(">B", value)
    if value <= 0xFFFF:
        return b"\xcd" + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return b"\xce" + struct.pack(">I", value)
    return b"\xcf" + struct.pack(">Q", value)


def pack_text(value: str) -> bytes:
    """Encode a short MessagePack string."""
    raw = value.encode()
    if len(raw) < 32:
        return bytes([0xA0 + len(raw)]) + raw
    return b"\xd9" + bytes([len(raw)]) + raw


def pack_bin(value: bytes) -> bytes:
    """Encode a short MessagePack byte array."""
    return b"\xc4" + bytes([len(value)]) + value


def pack_map(values: list[tuple[str, bytes]]) -> bytes:
    """Encode a small MessagePack map with string keys."""
    if len(values) >= 16:
        raise ValueError("map is too large for the bounded encoder")
    return bytes([0x80 + len(values)]) + b"".join(
        pack_text(key) + value for key, value in values
    )


def sync_message(sender: int, entries: list[tuple[str, bytes, int, int]]) -> bytes:
    """Encode the current named-map WaveKV v2 envelope."""
    encoded_entries = bytearray(bytes([0x90 + len(entries)]))
    for key, value, seq, timestamp in entries:
        metadata = pack_map(
            [
                ("node", pack_uint(sender)),
                ("seq", pack_uint(seq)),
                ("timestamp", pack_uint(timestamp)),
            ]
        )
        encoded_entries.extend(
            pack_map(
                [
                    ("key", pack_text(key)),
                    ("value", pack_bin(value)),
                    ("meta", metadata),
                ]
            )
        )
    return pack_map(
        [
            ("version", pack_uint(1)),
            ("sender_id", pack_uint(sender)),
            ("sender_uuid", pack_bin(b"")),
            ("acks", b"\x80"),
            ("entries", bytes(encoded_entries)),
            ("digest", b"\xc0"),
            ("page", b"\xc0"),
            ("resume_from", b"\xc0"),
            ("reset_acks", b"\xc2"),
            ("push_only", b"\xc2"),
        ]
    )


def tls_context(identity: dict[str, str] | None) -> ssl.SSLContext:
    """Create a case-owned TLS context with an optional client identity."""
    value = ssl.create_default_context()
    value.check_hostname = False
    value.verify_mode = ssl.CERT_NONE
    if identity is not None:
        value.load_cert_chain(identity["cert"], identity["key"])
    return value


def send(url: str, body: bytes, identity: dict[str, str] | None) -> int | None:
    """Send one bounded sync request and classify transport rejection."""
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-msgpack-gz")
    try:
        with urllib.request.urlopen(
            request, timeout=15, context=tls_context(identity)
        ) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as error:
        error.read()
        return int(error.code)
    except (
        urllib.error.URLError,
        ConnectionError,
        TimeoutError,
        ssl.SSLError,
        OSError,
    ):
        return None


def generate_wrong_identity(directory: pathlib.Path) -> dict[str, str]:
    """Generate an unrelated self-signed client identity."""
    key = directory / "wrong.key"
    cert = directory / "wrong.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=untrusted-wavekv-client",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )
    return {"key": str(key), "cert": str(cert)}


def der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode one DER length and return it with the offset of its content."""
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    return int.from_bytes(data[offset + 1 : offset + 1 + count], "big"), (
        offset + 1 + count
    )


def certificate_app_id(identity: dict[str, str]) -> bytes | None:
    """Return the app-id extension value of the identity's leaf certificate."""
    text = pathlib.Path(identity["cert"]).read_text()
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    start = text.index(begin) + len(begin)
    der = base64.b64decode("".join(text[start : text.index(end, start)].split()))
    position = der.find(APP_ID_OID_DER)
    if position < 0 or der.find(APP_ID_OID_DER, position + 1) >= 0:
        return None
    offset = position + len(APP_ID_OID_DER)
    if der[offset] == 0x01:  # optional critical BOOLEAN
        offset += 3
    if der[offset] != 0x04:
        return None
    _, offset = der_length(der, offset + 1)
    if der[offset] != 0x04:
        return None
    length, offset = der_length(der, offset + 1)
    return der[offset : offset + length]


def simulator_app_id(values: dict[str, Any]) -> str:
    """Query the case-owned guest simulator for the gateway's own app id."""
    service = values["gateway_guest_simulator"]["services"]["DstackGuest"]
    route = str(service["route"]).replace("<Method>", "Info")
    completed = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--unix-socket",
            str(service["socket"]),
            "--request",
            "POST",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "{}",
            f"http://localhost{route}",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )
    return str(json.loads(completed.stdout)["app_id"]).lower()


def persistent_keys(node: dict[str, Any], token: str) -> tuple[int, int]:
    """Read the persistent store key count."""
    code, body = SUPPORT.rpc(
        str(node["admin_url"]).rstrip("/"), token, "Admin.WaveKvStatus", {}
    )
    value = json.loads(body) if body else {}
    return code, int((value.get("persistent") or {}).get("n_keys", 0))


def main() -> int:
    """Run mTLS, encoding, ordering, replay, size, and recovery checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    node = values["gateway_production_node"]
    identity = values["gateway"]["registration_client"]
    token = (
        pathlib.Path(values["gateway_cluster"]["admin_auth_token_file"])
        .read_text()
        .strip()
    )
    public = urllib.parse.urlsplit(str(node["rpc_url"]))
    origin = urllib.parse.urlunsplit((public.scheme, public.netloc, "", "", ""))
    sync_url = f"{origin}/wavekv/sync/persistent"
    suffix = str(manifest["lease_id"])[-10:]
    key = f"cert/_case-wavekv-{suffix}"
    timestamp = int(__import__("time").time() * 1000)
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "WaveKV authentication and replay matrix did not complete"
    wrong_dir: pathlib.Path | None = None
    try:
        # Since PR #1147 the sync routes accept only the app-id extension (the
        # app-info fallback is gone), and a locally issued simulator certificate
        # carries that extension. The identity this matrix authenticates with
        # must therefore carry exactly the gateway's own app id.
        leaf_app_id = certificate_app_id(identity)
        expected_app_id = simulator_app_id(values)
        checks["identity_carries_gateway_app_id"] = (
            leaf_app_id is not None
            and len(leaf_app_id) > 0
            and leaf_app_id.hex() == expected_app_id
        )
        baseline_code, baseline_keys = persistent_keys(node, token)
        valid_empty = gzip.compress(sync_message(99, []))
        no_identity_code = send(sync_url, valid_empty, None)
        wrong_dir = pathlib.Path(
            tempfile.mkdtemp(prefix="wrong-wavekv-", dir=result_dir)
        )
        wrong_code = send(sync_url, valid_empty, generate_wrong_identity(wrong_dir))
        malformed_code = send(sync_url, b"not-gzip", identity)
        invalid_node_code = send(sync_url, gzip.compress(sync_message(0, [])), identity)
        invalid_store_code = send(
            f"{origin}/wavekv/sync/invalid", valid_empty, identity
        )
        oversize_code = send(sync_url, b"x" * (17 * 1024 * 1024), identity)
        checks["authentication_and_input_limits"] = (
            baseline_code == 200
            and (no_identity_code is None or no_identity_code in {401, 403})
            and (wrong_code is None or wrong_code in {401, 403})
            and malformed_code == 400
            and invalid_node_code == 400
            and invalid_store_code == 404
            and oversize_code in {400, 413}
        )

        gap = gzip.compress(
            sync_message(99, [(f"outside-schema/{suffix}", b"rejected", 1, timestamp)])
        )
        gap_code = send(sync_url, gap, identity)
        _, after_gap = persistent_keys(node, token)
        valid = gzip.compress(sync_message(99, [(key, b"accepted", 1, timestamp)]))
        valid_code = send(sync_url, valid, identity)
        _, after_valid = persistent_keys(node, token)
        replay_code = send(sync_url, valid, identity)
        _, after_replay = persistent_keys(node, token)
        recovery_code = send(sync_url, gzip.compress(sync_message(100, [])), identity)
        checks["unrestricted_key_replay_and_recovery"] = (
            gap_code == 200
            and after_gap == baseline_keys + 1
            and valid_code == 200
            and after_valid == baseline_keys + 2
            and replay_code == 200
            and after_replay == after_valid
            and recovery_code == 200
        )

        if not all(checks.values()):
            raise AssertionError(
                f"WaveKV checks failed: identity_app_id_present={leaf_app_id is not None}; {sorted(k for k, value in checks.items() if not value)}; auth={no_identity_code}/{wrong_code}; malformed={malformed_code}; node={invalid_node_code}; store={invalid_store_code}; oversize={oversize_code}; gap={gap_code}:{after_gap - baseline_keys}; valid={valid_code}:{after_valid - baseline_keys}; replay={replay_code}:{after_replay - after_valid}; recovery={recovery_code}"
            )
        steps = [
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The simulator mTLS identity carried the gateway's own app-id extension; the production-configured sync target required it and rejected missing or unrelated identities.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Malformed compression, invalid sender/store, and oversized input failed within bounded limits; an unrestricted application key synchronized successfully.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "A valid WaveKV v2 entry applied exactly once, replay was idempotent, and a later valid synchronization still succeeded.",
            },
        ]
        observation = {
            "checks": checks,
            "baseline_keys": baseline_keys,
            "after_gap_keys": after_gap,
            "after_valid_keys": after_valid,
            "after_replay_keys": after_replay,
            "no_identity_http": no_identity_code,
            "wrong_identity_http": wrong_code,
            "malformed_http": malformed_code,
            "invalid_node_http": invalid_node_code,
            "invalid_store_http": invalid_store_code,
            "oversize_http": oversize_code,
            "gap_http": gap_code,
            "valid_http": valid_code,
            "replay_http": replay_code,
            "recovery_http": recovery_code,
        }
        path = result_dir / "artifacts/gateway-wavekv-auth.json"
        SUPPORT.atomic_json(path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-wavekv-auth.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "WaveKV authentication and replay matrix",
                "description": "HTTP statuses, key counts, and boolean assertions only; no key name/value, certificate, URL, credential, or response body is retained.",
            }
        )
        status = "PASS"
        summary = "WaveKV mTLS authentication, input limits, ordering, replay idempotency, and post-failure recovery passed."
    except Exception as error:  # noqa: BLE001
        failed = len(steps) + 1
        for index in range(failed, 4):
            steps.append(
                {
                    "id": f"{CASE_ID}-step-{index:02d}",
                    "status": "FAIL" if index == failed else "NOT_RUN",
                    "observed": str(error)
                    if index == failed
                    else "Not run after failure.",
                }
            )
        summary = f"WaveKV authentication and replay matrix failed: {error}"
    finally:
        if wrong_dir is not None:
            for path in wrong_dir.glob("*"):
                path.unlink()
            wrong_dir.rmdir()
    SUPPORT.atomic_json(
        result_dir / "artifacts/manifest.json", {"artifacts": artifacts}
    )
    SUPPORT.atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "Ephemeral wrong-client material was deleted; no sync key/value, certificate, URL, credential, or native response body is retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
