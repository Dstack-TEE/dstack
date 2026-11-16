#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D103
"""Compare the live VMM OpenAPI document with prepared public routes."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-vmm-internal-007"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        tmp = pathlib.Path(out.name)
    tmp.replace(path)


def request(
    url: str, headers: dict[str, str], body: bytes | None = None
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main() -> int:
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm["json_prpc_routes"]
    headers = {
        str(k): str(v) for k, v in vmm.get("auth", {}).get("headers", {}).items()
    }
    failures = []
    steps = []
    evidence = {}
    try:
        code, raw = request(base + "/api-docs/openapi.json", headers)
        document = json.loads(raw)
        paths = document.get("paths", {}) if isinstance(document, dict) else {}
        info = document.get("info", {}) if isinstance(document, dict) else {}
        if (
            code != 200
            or not isinstance(paths, dict)
            or not paths
            or not info.get("version")
        ):
            raise AssertionError("live OpenAPI document was incomplete")
        evidence["document"] = {
            "http": code,
            "openapi": document.get("openapi"),
            "title": info.get("title"),
            "version": info.get("version"),
            "path_count": len(paths),
        }
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Fetched the candidate VMM's live versioned OpenAPI document from its case-owned listener.",
            }
        )
        documented = set(paths)
        missing = []
        for method, route in routes.items():
            path = route.split("?", 1)[0]
            if path not in documented and not any(
                p.rstrip("/").endswith("/" + method) for p in documented
            ):
                missing.append(method)
        if missing:
            raise AssertionError(
                f"prepared public routes absent from OpenAPI: {missing}"
            )
        evidence["agreement"] = {
            "prepared_route_count": len(routes),
            "missing_methods": missing,
        }
        steps.append(
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Every prepared public JSON pRPC method had a corresponding live OpenAPI path.",
            }
        )
        version_route = routes["Version"].split("?", 1)[0]
        version_code, version_raw = request(
            base + version_route, {"content-type": "application/json", **headers}, b"{}"
        )
        bad_code, _ = request(
            base + version_route + "NoSuch",
            {"content-type": "application/json", **headers},
            b"{}",
        )
        if (
            version_code != 200
            or not json.loads(version_raw or b"{}").get("version")
            or bad_code < 400
        ):
            raise AssertionError(
                "documented or invalid live request behavior mismatched"
            )
        evidence["live"] = {
            "version_http": version_code,
            "invalid_route_http": bad_code,
        }
        steps.append(
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "A documented Version request succeeded and an adjacent undocumented route failed closed.",
            }
        )
        code2, raw2 = request(base + "/api-docs/openapi.json", headers)
        if code2 != 200 or raw2 != raw:
            raise AssertionError("repeated OpenAPI document changed")
        evidence["repeat_identical"] = True
        evidence["sensitive_values_persisted"] = False
        steps.append(
            {
                "id": f"{CASE_ID}-step-04",
                "status": "PASS",
                "observed": "Repeated live document retrieval was byte-identical and the listener remained available after the negative request.",
            }
        )
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for n in range(1, 5):
            sid = f"{CASE_ID}-step-{n:02d}"
            if not any(x["id"] == sid for x in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    artifact = {
        "path": "artifacts/vmm-live-openapi.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Live VMM OpenAPI agreement",
        "description": "Versioned live document metadata, prepared-route agreement, bounded live requests, deterministic repeat, and redaction assertion.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": "Live OpenAPI and prepared VMM routes agree."
            if not failures
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only schema metadata and HTTP status codes were retained.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
