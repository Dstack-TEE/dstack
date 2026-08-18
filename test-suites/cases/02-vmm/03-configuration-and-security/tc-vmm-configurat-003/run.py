#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Exercise per-instance simulated TEE selection through the public VMM API."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-vmm-configurat-003"
VARIANTS = (
    "dstack-tdx",
    "dstack-gcp-tdx",
    "dstack-nitro-enclave",
    "dstack-amd-sev-snp",
    "dstack-aws-nitro-tpm",
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = pathlib.Path(handle.name)
    temporary.replace(path)


def call(url: str, value: dict[str, Any], headers: dict[str, str]) -> tuple[int, bytes]:
    """Perform one bounded JSON pRPC call."""
    request = urllib.request.Request(
        url, data=json.dumps(value).encode(), method="POST"
    )
    request.add_header("Content-Type", "application/json")
    for key, header_value in headers.items():
        request.add_header(key, header_value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def list_ids(manifest: dict[str, Any]) -> set[str]:
    """List persisted VM IDs using the fixture's authoritative command."""
    process = subprocess.run(
        manifest["values"]["vmm"]["commands"]["list_vms"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(f"list_vms failed: {process.stderr[-300:]}")
    return {
        str(item.get("id"))
        for item in json.loads(process.stdout or "[]")
        if isinstance(item, dict)
    }


def main() -> int:
    """Create the simulator matrix, verify isolation, reject invalid rows, clean up."""
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
    template = json.loads(json.dumps(vmm["test_input"]["vm_configuration"]))
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm.get("json_prpc_routes") or {}
    create_url = base + (routes.get("CreateVm") or "/prpc/CreateVm?json")
    info_url = base + (routes.get("GetInfo") or "/prpc/GetInfo?json")
    remove_url = base + (routes.get("RemoveVm") or "/prpc/RemoveVm?json")
    headers: dict[str, str] = {}
    auth = vmm.get("auth") or {}
    if auth.get("enabled") and auth.get("token_file"):
        token = pathlib.Path(auth["token_file"]).read_text().strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"

    nonce = hashlib.sha256(f"{time.time_ns()}:{case_id}".encode()).hexdigest()[:12]
    baseline: set[str] = set()
    created: list[str] = []
    evidence: dict[str, Any] = {}
    steps: list[dict[str, str]] = []
    failure: str | None = None

    def create_row(label: str, variant: str | None, no_tee: bool) -> tuple[str, str]:
        request = json.loads(json.dumps(template))
        request["name"] = f"dtest-{nonce}-{label}"
        request["stopped"] = True
        request["no_tee"] = no_tee
        request.pop("simulated_tee", None)
        if variant is not None:
            request["simulated_tee"] = variant
        code, body = call(create_url, request, headers)
        value = json.loads(body or b"{}")
        vm_id = value.get("id") if isinstance(value, dict) else None
        if code != 200 or not vm_id:
            raise AssertionError(
                f"{label} CreateVm returned HTTP {code}: "
                f"{body.decode('utf-8', 'replace')[:200]}"
            )
        return str(vm_id), label

    try:
        baseline = list_ids(manifest)
        evidence["baseline_count"] = len(baseline)
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The case-owned VMM was reachable before the run-scoped matrix was created.",
            }
        )

        rows = [(variant, variant, False) for variant in VARIANTS]
        rows += [("real-control", None, False), ("no-tee-control", None, True)]
        labels: dict[str, str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(rows)) as pool:
            futures = [pool.submit(create_row, *row) for row in rows]
            for future in concurrent.futures.as_completed(futures):
                vm_id, label = future.result()
                created.append(vm_id)
                labels[vm_id] = label

        observed: dict[str, dict[str, Any]] = {}
        for vm_id, label in labels.items():
            code, body = call(info_url, {"id": vm_id}, headers)
            if code != 200:
                raise AssertionError(f"{label} GetInfo returned HTTP {code}")
            value = json.loads(body or b"{}")
            info = value.get("info") if isinstance(value, dict) else None
            config = info.get("configuration") if isinstance(info, dict) else None
            if not isinstance(config, dict):
                raise AssertionError(f"{label} GetInfo omitted configuration")
            expected_variant = label if label in VARIANTS else None
            expected_no_tee = label != "real-control"
            actual_variant = config.get("simulated_tee")
            if actual_variant in ("", None):
                actual_variant = None
            if (
                actual_variant != expected_variant
                or config.get("no_tee") != expected_no_tee
            ):
                raise AssertionError(
                    f"{label} persisted simulated_tee={actual_variant!r}, "
                    f"no_tee={config.get('no_tee')!r}"
                )
            observed[label] = {
                "simulated_tee": actual_variant,
                "no_tee": config.get("no_tee"),
                "stopped": config.get("stopped"),
            }
        if set(list_ids(manifest)) != baseline | set(created):
            raise AssertionError("concurrent matrix did not remain case-scoped")
        evidence["matrix"] = observed
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Five simulator variants and two controls were created concurrently and persisted independent selections.",
            }
        )

        negative: dict[str, int] = {}
        for label, invalid in (("empty", ""), ("unknown", "not-a-platform")):
            request = json.loads(json.dumps(template))
            request["name"] = f"dtest-{nonce}-invalid-{label}"
            request["stopped"] = True
            request["simulated_tee"] = invalid
            code, _ = call(create_url, request, headers)
            negative[label] = code
            if code < 400:
                raise AssertionError(
                    f"invalid simulator row {label} returned HTTP {code}"
                )
        unauthenticated: int | None = None
        if headers:
            request = json.loads(json.dumps(template))
            request["name"] = f"dtest-{nonce}-unauth"
            request["stopped"] = True
            request["simulated_tee"] = VARIANTS[0]
            unauthenticated, _ = call(create_url, request, {})
            if unauthenticated < 400:
                raise AssertionError("unauthenticated simulator request was accepted")
        if set(list_ids(manifest)) != baseline | set(created):
            raise AssertionError("rejected simulator row left partial VM state")
        evidence["negative"] = {
            "http_statuses": negative,
            "unauthenticated_http": unauthenticated,
            "no_partial_state": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Empty, unknown, and applicable unauthenticated inputs were rejected without cross-instance or partial state.",
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
        statuses: list[int] = []
        for vm_id in created:
            code, _ = call(remove_url, {"id": vm_id}, headers)
            statuses.append(code)
        deadline = time.monotonic() + 30
        while set(created) & list_ids(manifest) and time.monotonic() < deadline:
            time.sleep(1)
        all_absent = not bool(set(created) & list_ids(manifest))
        evidence["cleanup"] = {
            "http_statuses": sorted(statuses),
            "all_absent": all_absent,
        }
        if (
            any(code != 200 for code in statuses) or not all_absent
        ) and failure is None:
            failure = "cleanup failed to remove every matrix VM"

    artifact = {
        "path": "artifacts/simulated-tee-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Per-instance simulated TEE matrix",
        "description": "Records concurrent selections, controls, rejection paths, state isolation, and cleanup.",
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
                "All supported simulated TEE selections were isolated per instance and invalid selections were rejected."
                if status == "PASS"
                else failure
            ),
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "All VMs and the VMM are lease-owned; every successful row is removed after verification.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
