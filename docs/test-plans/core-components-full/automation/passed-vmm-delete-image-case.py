#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic DeleteImage state transitions in a lease-owned image store."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-vmm-vmm-023"


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


def encode_id(image_id: str) -> bytes:
    """Encode Id.id (field 1)."""
    raw = image_id.encode()
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


def list_images(
    base: str, routes: dict[str, str], headers: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """Return local images keyed by their public image name."""
    path = (routes.get("ListImages") or "/prpc/ListImages?json").split("?", 1)[0]
    code, body = call(base + path, b"{}", "application/json", headers)
    if code != 200:
        raise RuntimeError(f"ListImages returned HTTP {code}")
    value = json.loads(body or b"{}")
    rows = value.get("images") if isinstance(value, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("ListImages response did not contain images")
    return {str(row.get("name")): row for row in rows if isinstance(row, dict)}


def main() -> int:
    """Delete two independently provisioned images over JSON and protobuf."""
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
    images = vmm["test_input"].get("deletable_images") or []
    if not isinstance(images, list) or len(images) != 2 or len(set(images)) != 2:
        raise RuntimeError("fixture did not provide two distinct disposable images")
    json_image, protobuf_image = map(str, images)
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm.get("json_prpc_routes") or {}
    path = (routes.get("DeleteImage") or "/prpc/DeleteImage?json").split("?", 1)[0]
    headers: dict[str, str] = {}
    auth = vmm.get("auth") or {}
    token_file = auth.get("token_file")
    if auth.get("enabled") and token_file:
        token = pathlib.Path(token_file).read_text().strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    evidence: dict[str, Any] = {"disposable_images": images}
    steps: list[dict[str, str]] = []
    failure: str | None = None
    try:
        baseline = list_images(base, routes, headers)
        missing = sorted(set(images) - set(baseline))
        if missing:
            raise AssertionError(f"disposable images were not listed: {missing}")
        evidence["baseline_names"] = sorted(baseline)
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Both lease-owned disposable images were listed before mutation.",
            }
        )

        json_code, json_body = call(
            base + path,
            json.dumps({"id": json_image, "future_field": "ignored"}).encode(),
            "application/json",
            headers,
        )
        if json_code != 200 or json_body not in (b"", b"null"):
            raise AssertionError(
                f"JSON deletion returned HTTP {json_code} and {len(json_body)} bytes"
            )
        after_json = list_images(base, routes, headers)
        if json_image in after_json or protobuf_image not in after_json:
            raise AssertionError("JSON deletion was not isolated to its target image")
        protobuf_code, protobuf_body = call(
            base + path,
            encode_id(protobuf_image),
            "application/octet-stream",
            headers,
        )
        if protobuf_code != 200 or protobuf_body:
            raise AssertionError(
                f"protobuf deletion returned HTTP {protobuf_code} and "
                f"{len(protobuf_body)} bytes"
            )
        after_protobuf = list_images(base, routes, headers)
        if set(images) & set(after_protobuf):
            raise AssertionError("protobuf deletion left a disposable image listed")
        unrelated = set(baseline) - set(images)
        if unrelated != set(after_protobuf):
            raise AssertionError("deletion changed unrelated image inventory")
        evidence["representations"] = {
            "json_http": json_code,
            "after_json_names": sorted(after_json),
            "protobuf_http": protobuf_code,
            "after_protobuf_names": sorted(after_protobuf),
            "unrelated_unchanged": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "JSON and protobuf independently removed their exact disposable image without changing unrelated inventory.",
            }
        )

        repeat_json, _ = call(
            base + path,
            json.dumps({"id": json_image}).encode(),
            "application/json",
            headers,
        )
        wrong_type, _ = call(
            base + path, json.dumps({"id": 7}).encode(), "application/json", headers
        )
        traversal, _ = call(
            base + path,
            json.dumps({"id": "../outside"}).encode(),
            "application/json",
            headers,
        )
        malformed, _ = call(
            base + path, b"\x0a\x80", "application/octet-stream", headers
        )
        bad_route, _ = call(base + path + "NoSuch", b"{}", "application/json", headers)
        statuses = [repeat_json, wrong_type, traversal, malformed, bad_route]
        if min(statuses) < 400:
            raise AssertionError(f"invalid deletion probe was accepted: {statuses}")
        if set(list_images(base, routes, headers)) != unrelated:
            raise AssertionError("rejected deletion probes changed image inventory")
        evidence["negative"] = {
            "repeat_missing_http": repeat_json,
            "wrong_type_http": wrong_type,
            "traversal_http": traversal,
            "malformed_protobuf_http": malformed,
            "invalid_route_http": bad_route,
            "inventory_unchanged": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Missing, wrong-typed, traversal, malformed-protobuf, and invalid-route requests were rejected without inventory changes.",
            }
        )
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        done = {step["id"] for step in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in done:
                steps.append({"id": step_id, "status": "FAIL", "observed": failure})

    artifact = {
        "path": "artifacts/delete-image-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Delete image matrix",
        "description": "Records independent JSON/protobuf transitions, rejection probes, and unaffected inventory.",
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
                "Vmm.DeleteImage removed two disposable images over JSON and protobuf while preserving unrelated inventory."
                if status == "PASS"
                else failure
            ),
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Both image directories and the VMM are lease-owned; successful deletion is the cleanup.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
