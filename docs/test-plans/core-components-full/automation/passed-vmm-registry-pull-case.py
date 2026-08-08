#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic registry-image pull lifecycle for a lease-owned VMM."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-vmm-vmm-022"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = pathlib.Path(handle.name)
    temporary.replace(path)


def varint(value: int) -> bytes:
    """Encode a protobuf unsigned varint."""
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        output.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(output)


def encode_tag(tag: str) -> bytes:
    """Encode PullRegistryImageRequest.tag (field 1)."""
    raw = tag.encode()
    return varint((1 << 3) | 2) + varint(len(raw)) + raw


def call(
    url: str, body: bytes, content_type: str, headers: dict[str, str]
) -> tuple[int, bytes]:
    """Perform one bounded pRPC request."""
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", content_type)
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def image_status(
    base: str, routes: dict[str, str], headers: dict[str, str], tag: str
) -> dict[str, Any]:
    """Return the exact registry row for the fixture tag."""
    path = (routes.get("ListRegistryImages") or "/prpc/ListRegistryImages?json").split(
        "?", 1
    )[0]
    code, body = call(base + path, b"{}", "application/json", headers)
    if code != 200:
        raise RuntimeError(f"ListRegistryImages returned HTTP {code}")
    value = json.loads(body or b"{}")
    rows = value.get("images") if isinstance(value, dict) else None
    matches = [row for row in (rows or []) if row.get("tag") == tag]
    if len(matches) != 1:
        raise AssertionError(f"registry tag {tag!r} had {len(matches)} rows")
    return matches[0]


def await_local(
    base: str,
    routes: dict[str, str],
    headers: dict[str, str],
    tag: str,
    wanted: bool,
    timeout: int = 60,
) -> dict[str, Any]:
    """Poll until the fixture tag reaches its requested local state."""
    deadline = time.monotonic() + timeout
    observed: dict[str, Any] = {}
    while time.monotonic() < deadline:
        observed = image_status(base, routes, headers, tag)
        error = str(observed.get("error") or "")
        if error:
            raise AssertionError(f"registry pull failed: {error[:300]}")
        if bool(observed.get("local")) is wanted and not observed.get("pulling"):
            return observed
        time.sleep(1)
    raise AssertionError(f"registry tag did not reach local={wanted}: {observed}")


def main() -> int:
    """Exercise PullRegistryImage over JSON and protobuf."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    if vmm.get("case_owned") is not True:
        raise RuntimeError("VMM fixture is not case-owned")
    tag = str(vmm["test_input"].get("registry_tag") or "")
    registry = str(vmm["test_input"].get("registry") or "")
    if not tag or not registry:
        raise RuntimeError("fixture did not provide a registry and disposable tag")
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm.get("json_prpc_routes") or {}
    headers: dict[str, str] = {}
    auth = vmm.get("auth") or {}
    token_file = auth.get("token_file")
    if auth.get("enabled") and token_file:
        token = pathlib.Path(token_file).read_text().strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    pull_path = (
        routes.get("PullRegistryImage") or "/prpc/PullRegistryImage?json"
    ).split("?", 1)[0]
    delete_path = (routes.get("DeleteImage") or "/prpc/DeleteImage?json").split("?", 1)[
        0
    ]
    evidence: dict[str, Any] = {"tag": tag, "registry_configured": True}
    steps: list[dict[str, str]] = []
    failure: str | None = None

    def delete_local() -> int:
        code, body = call(
            base + delete_path,
            json.dumps({"id": tag}).encode(),
            "application/json",
            headers,
        )
        if code != 200:
            raise AssertionError(
                f"DeleteImage cleanup returned HTTP {code}: "
                f"{body.decode('utf-8', 'replace')[:300]}"
            )
        await_local(base, routes, headers, tag, False)
        return code

    try:
        baseline = image_status(base, routes, headers, tag)
        if baseline.get("pulling") or baseline.get("error"):
            raise AssertionError(
                f"fixture registry baseline was not healthy: {baseline}"
            )
        evidence["baseline"] = baseline
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The case-owned registry exposed exactly one healthy fixture tag.",
            }
        )

        json_code, json_body = call(
            base + pull_path,
            json.dumps({"tag": tag, "future_field": "ignored"}).encode(),
            "application/json",
            headers,
        )
        if json_code != 200 or json_body not in (b"", b"null"):
            raise AssertionError(
                f"JSON pull returned HTTP {json_code} and {len(json_body)} bytes"
            )
        json_final = await_local(base, routes, headers, tag, True)
        between_delete = delete_local()
        protobuf_code, protobuf_body = call(
            base + pull_path, encode_tag(tag), "application/octet-stream", headers
        )
        if protobuf_code != 200 or protobuf_body:
            raise AssertionError(
                f"protobuf pull returned HTTP {protobuf_code} and "
                f"{len(protobuf_body)} bytes"
            )
        protobuf_final = await_local(base, routes, headers, tag, True)
        evidence["representations"] = {
            "json_http": json_code,
            "json_final": json_final,
            "between_delete_http": between_delete,
            "protobuf_http": protobuf_code,
            "protobuf_final": protobuf_final,
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "JSON and protobuf pulls independently downloaded the fixture tag and reached local=true without an error.",
            }
        )

        wrong_type, _ = call(
            base + pull_path,
            json.dumps({"tag": 7}).encode(),
            "application/json",
            headers,
        )
        malformed, _ = call(
            base + pull_path, b"\x0a\x80", "application/octet-stream", headers
        )
        bad_route, _ = call(
            base + pull_path + "NoSuch", b"{}", "application/json", headers
        )
        if min(wrong_type, malformed, bad_route) < 400:
            raise AssertionError(
                f"invalid probes were accepted: {wrong_type}, {malformed}, {bad_route}"
            )
        healthy = image_status(base, routes, headers, tag)
        if not healthy.get("local") or healthy.get("pulling") or healthy.get("error"):
            raise AssertionError(
                f"invalid probes disturbed the pulled image: {healthy}"
            )
        evidence["negative"] = {
            "wrong_type_http": wrong_type,
            "malformed_protobuf_http": malformed,
            "invalid_route_http": bad_route,
            "healthy_after": healthy,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Wrong-typed JSON, malformed protobuf, and an invalid route were rejected without disturbing the pulled image.",
            }
        )
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        done = {step["id"] for step in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in done:
                steps.append({"id": step_id, "status": "FAIL", "observed": failure})
    finally:
        try:
            if image_status(base, routes, headers, tag).get("local"):
                evidence["cleanup_http"] = delete_local()
        except Exception as error:  # noqa: BLE001
            if failure is None:
                failure = f"cleanup {type(error).__name__}: {error}"

    artifact = {
        "path": "artifacts/registry-pull-lifecycle.json",
        "step_id": f"{case_id}-step-02",
        "name": "Registry pull lifecycle",
        "description": "Records the fixture tag state across JSON/protobuf pulls, rejection probes, and cleanup.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if failure is None else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": (
                "Vmm.PullRegistryImage downloaded the fixture tag over JSON and protobuf and rejected malformed requests."
                if status == "PASS"
                else failure
            ),
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "The pulled image is deleted after verification; the mock registry and image store are lease-owned.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
