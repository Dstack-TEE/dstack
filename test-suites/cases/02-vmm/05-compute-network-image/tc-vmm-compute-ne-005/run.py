#!/usr/bin/env python3
# ruff: noqa: D103
# SPDX-License-Identifier: Apache-2.0
"""Verify case-owned local image discovery, metadata filtering, and deletion safety."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-vmm-compute-ne-005"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        tmp = pathlib.Path(out.name)
    tmp.replace(path)


def call(
    base: str, headers: dict[str, str], route: str, body: dict[str, Any]
) -> tuple[int, bytes]:
    req = urllib.request.Request(
        base + route.split("?", 1)[0],
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def list_images(
    base: str, headers: dict[str, str], route: str
) -> dict[str, dict[str, Any]]:
    code, raw = call(base, headers, route, {})
    if code != 200:
        raise AssertionError("ListImages failed")
    value = json.loads(raw or b"{}")
    rows = value.get("images", []) if isinstance(value, dict) else []
    return {str(x.get("name")): x for x in rows if isinstance(x, dict)}


def create(test_input: dict[str, Any], image: str) -> str:
    p = subprocess.run(
        [
            *map(str, test_input["create_stopped_helper_argv"]),
            "--name",
            f"{test_input.get('name_prefix', 'dtest')}-image-in-use",
            "--image",
            image,
        ],
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if p.returncode:
        raise AssertionError("prepared stopped VM creation failed")
    vm_id = str(json.loads(p.stdout.splitlines()[-1])["id"])
    registry = json.loads(pathlib.Path(test_input["created_vms_registry"]).read_text())
    if vm_id not in registry:
        raise AssertionError("VM ID was not immediately registered")
    return vm_id


def main() -> int:
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    if vmm.get("case_owned") is not True:
        raise RuntimeError("VMM is not case-owned")
    test_input = vmm["test_input"]
    matrix = test_input["discovery_images"]
    unused = str(matrix["unused_image"])
    invalid = str(matrix["invalid_image"])
    in_use = str(matrix["in_use_image"])
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm["json_prpc_routes"]
    headers = {
        str(k): str(v) for k, v in vmm.get("auth", {}).get("headers", {}).items()
    }
    vm_id = None
    failures = []
    steps = []
    evidence = {"matrix": matrix}
    try:
        baseline = list_images(base, headers, routes["ListImages"])
        evidence["baseline"] = {
            "names": sorted(baseline),
            "unused_present": unused in baseline,
            "in_use_present": in_use in baseline,
            "invalid_absent": invalid not in baseline,
        }
        if unused not in baseline or in_use not in baseline or invalid in baseline:
            raise AssertionError("discovery metadata filtering mismatch")
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The valid unused and candidate images were listed while the fixture's invalid metadata directory was excluded.",
            }
        )
        vm_id = create(test_input, in_use)
        delete_unused, _ = call(base, headers, routes["DeleteImage"], {"id": unused})
        after_unused = list_images(base, headers, routes["ListImages"])
        delete_in_use, _ = call(base, headers, routes["DeleteImage"], {"id": in_use})
        after_in_use = list_images(base, headers, routes["ListImages"])
        traversal, _ = call(base, headers, routes["DeleteImage"], {"id": "../outside"})
        wrong_type, _ = call(base, headers, routes["DeleteImage"], {"id": 7})
        if delete_unused != 200 or unused in after_unused:
            raise AssertionError("unused image deletion failed")
        if delete_in_use < 400 or in_use not in after_in_use:
            raise AssertionError("in-use image deletion did not fail safely")
        if traversal < 400 or wrong_type < 400:
            raise AssertionError("invalid image ID was accepted")
        evidence["operations"] = {
            "delete_unused": delete_unused,
            "unused_absent": True,
            "delete_in_use": delete_in_use,
            "in_use_retained": True,
            "traversal": traversal,
            "wrong_type": wrong_type,
            "invalid_metadata_absent": True,
        }
        steps.append(
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Deleted only the valid unused image; an immediately registered stopped VM made the candidate image in-use and its deletion was rejected without mutation.",
            }
        )
        final = list_images(base, headers, routes["ListImages"])
        if invalid in final or unused in final or in_use not in final:
            raise AssertionError("final image inventory violated isolation")
        evidence["final_names"] = sorted(final)
        evidence["sensitive_values_persisted"] = False
        steps.append(
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Traversal and wrong-typed IDs failed closed; final inventory retained the in-use image, excluded invalid metadata, and the public service remained available.",
            }
        )
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for n in range(1, 4):
            sid = f"{CASE_ID}-step-{n:02d}"
            if not any(x["id"] == sid for x in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    finally:
        if vm_id:
            stop, _ = call(base, headers, routes["StopVm"], {"id": vm_id})
            remove, _ = call(base, headers, routes["RemoveVm"], {"id": vm_id})
            evidence["cleanup"] = {"stop": stop, "remove": remove}
    artifact = {
        "path": "artifacts/vmm-image-discovery.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "VMM image discovery lifecycle",
        "description": "Public inventory and HTTP evidence for metadata filtering, unused deletion, in-use protection, invalid IDs, isolation, and cleanup.",
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
            "summary": "Local image discovery and deletion safety passed."
            if not failures
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only the fixture-owned unused image and immediately registered VM were mutated.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
