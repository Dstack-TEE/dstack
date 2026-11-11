#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic VMM app update identity regression."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-vmm-vm-lifecyc-003"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def call(
    base: str, headers: dict[str, str], method: str, body: dict[str, Any]
) -> tuple[int, Any]:
    """Call one JSON pRPC method."""
    request = urllib.request.Request(
        f"{base}/prpc/{method}",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            return response.status, json.loads(raw or b"null")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw or b"null")
        except json.JSONDecodeError:
            return error.code, {"body_bytes": len(raw)}


def main() -> int:
    """Run promoted VMM update coverage."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    if vmm.get("case_owned") is not True:
        raise RuntimeError("VMM fixture is not case-owned")
    base = str(vmm["rpc_url"]).rstrip("/")
    headers = {
        str(key): str(value)
        for key, value in vmm.get("auth", {}).get("headers", {}).items()
    }
    template = json.loads(json.dumps(vmm["test_input"]["vm_configuration"]))
    nonce = hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:12]
    template.update({"name": f"dtest-{nonce}-update", "ports": [], "stopped": True})
    vm_id: str | None = None
    prealloc_id: str | None = None
    failures: list[str] = []
    steps: list[dict[str, str]] = []
    evidence: dict[str, Any] = {}
    try:
        create_code, created = call(base, headers, "CreateVm", template)
        vm_id = created.get("id") if isinstance(created, dict) else None
        if create_code != 200 or not vm_id:
            raise AssertionError("stopped VM creation failed")
        baseline_code, baseline = call(base, headers, "GetInfo", {"id": vm_id})
        if baseline_code != 200:
            raise AssertionError("baseline GetInfo failed")
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Created a stopped fixture-owned VM and captured its persisted configuration.",
            }
        )

        compose = json.loads(template["compose_file"])
        compose["promotion_nonce"] = nonce
        updated_compose = json.dumps(compose, separators=(",", ":"), sort_keys=True)
        expected_id = hashlib.sha256(updated_compose.encode()).hexdigest()[:40]
        update_code, updated = call(
            base,
            headers,
            "UpgradeApp",
            {"id": vm_id, "compose_file": updated_compose, "app_id": "0" * 40},
        )
        returned_id = updated.get("id") if isinstance(updated, dict) else None
        info_code, info = call(base, headers, "GetInfo", {"id": vm_id})
        stored = info.get("info", {}).get("configuration", {}).get("compose_file")
        evidence["update_observation"] = {
            "update_http": update_code,
            "info_http": info_code,
            "returned_id_matches": returned_id == expected_id,
            "stored_compose_matches": stored == updated_compose,
            "expected_compose_bytes": len(updated_compose.encode()),
            "stored_compose_bytes": len(stored.encode())
            if isinstance(stored, str)
            else None,
            "expected_compose_sha256": hashlib.sha256(
                updated_compose.encode()
            ).hexdigest(),
            "stored_compose_sha256": hashlib.sha256(stored.encode()).hexdigest()
            if isinstance(stored, str)
            else None,
        }
        if (
            update_code != 200
            or returned_id != expected_id
            or info_code != 200
            or stored != updated_compose
        ):
            raise AssertionError("compose-derived update identity did not persist")
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "UpgradeApp ignored caller app_id, returned the compose-derived id, and persisted the exact compose.",
            }
        )

        malformed, _ = call(
            base, headers, "UpgradeApp", {"id": vm_id, "compose_file": "{"}
        )
        missing, _ = call(
            base,
            headers,
            "UpgradeApp",
            {
                "id": "00000000-0000-0000-0000-000000000000",
                "compose_file": updated_compose,
            },
        )
        repeat, repeated = call(
            base, headers, "UpgradeApp", {"id": vm_id, "compose_file": updated_compose}
        )
        if (
            malformed < 400
            or missing < 400
            or repeat != 200
            or repeated.get("id") != expected_id
        ):
            raise AssertionError("negative or repeat update behavior failed")
        # PR #1230: a VM deployed with a block-reserving preallocation keeps
        # its mode for life, so an update may not turn guest discard back on.
        # The refusal comes before the compose file is written.
        no_discard = json.loads(template["compose_file"])
        no_discard["storage_discard"] = False
        prealloc_code, prealloc = call(
            base,
            headers,
            "CreateVm",
            {
                **template,
                "name": f"dtest-{nonce}-prealloc",
                "compose_file": json.dumps(no_discard),
                "disk_prealloc": "falloc",
            },
        )
        prealloc_id = prealloc.get("id") if isinstance(prealloc, dict) else None
        if prealloc_code != 200 or not prealloc_id:
            raise AssertionError("falloc VM without discard was refused")
        discard_on = {**no_discard, "storage_discard": True}
        discard_code, discard_body = call(
            base,
            headers,
            "UpgradeApp",
            {"id": prealloc_id, "compose_file": json.dumps(discard_on)},
        )
        discard_error = str(discard_body.get("error", ""))[:300]
        _, prealloc_info = call(base, headers, "GetInfo", {"id": prealloc_id})
        prealloc_config = prealloc_info.get("info", {}).get("configuration", {})
        kept_code, _ = call(
            base,
            headers,
            "UpgradeApp",
            {
                "id": prealloc_id,
                "compose_file": json.dumps({**no_discard, "promotion_nonce": nonce}),
            },
        )
        evidence["prealloc_update"] = {
            "create": prealloc_code,
            "discard_on_update": discard_code,
            "discard_on_error": discard_error,
            "compose_unchanged": prealloc_config.get("compose_file")
            == json.dumps(no_discard),
            "persisted_mode": prealloc_config.get("disk_prealloc"),
            "discard_off_update": kept_code,
        }
        if (
            discard_code < 400
            or "storage_discard = false" not in discard_error
            or not evidence["prealloc_update"]["compose_unchanged"]
            or prealloc_config.get("disk_prealloc") != "falloc"
            or kept_code != 200
        ):
            raise AssertionError(
                f"preallocated VM update was not gated: {evidence['prealloc_update']}"
            )
        evidence["matrix"] = {
            "create": create_code,
            "baseline": baseline_code,
            "update": update_code,
            "info": info_code,
            "malformed": malformed,
            "missing": missing,
            "repeat": repeat,
            "derived_id_matches": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Malformed and missing-VM updates failed closed; repeated update converged to the same id; a falloc VM refused a compose that re-enabled discard and kept its stored compose.",
            }
        )
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if not any(step["id"] == step_id for step in steps):
                steps.append(
                    {"id": step_id, "status": "FAIL", "observed": failures[-1]}
                )
    finally:
        evidence["cleanup"] = {
            name: call(base, headers, "RemoveVm", {"id": created_id})[0]
            for name, created_id in (("update", vm_id), ("prealloc", prealloc_id))
            if created_id
        }
    artifact = {
        "path": "artifacts/vmm-update-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "VMM update matrix",
        "description": "Bounded status and identity assertions for app update, negative inputs, repeatability, and cleanup.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "VMM app update identity regression passed."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only one stopped VM owned by the isolated fixture was mutated and removed.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
