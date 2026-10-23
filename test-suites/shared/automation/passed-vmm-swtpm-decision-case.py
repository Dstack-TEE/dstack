#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Exercise deployment-time swtpm materialization for simulated platforms."""

from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util
import json
import os
import pathlib
import time
from typing import Any

CASE = "tc-vmm-configurat-004"
MATRIX = {
    "dstack-tdx": True,
    "dstack-gcp-tdx": False,
    "dstack-nitro-enclave": True,
    "dstack-amd-sev-snp": True,
    "dstack-aws-nitro-tpm": False,
}


def load_common() -> Any:
    """Load the adjacent checked-in VMM JSON pRPC helpers."""
    path = pathlib.Path(__file__).with_name("passed-vmm-simulated-tee-case.py")
    spec = importlib.util.spec_from_file_location("vmm_simulated_tee_common", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load VMM harness helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    """Create the TPM matrix, verify manifests, reject invalid input, clean up."""
    common = load_common()
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    case_manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = case_manifest["values"]["vmm"]
    if vmm.get("case_owned") is not True:
        raise RuntimeError("VMM fixture is not case-owned")
    template = json.loads(json.dumps(vmm["test_input"]["vm_configuration"]))
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm.get("json_prpc_routes") or {}
    create_url = base + (routes.get("CreateVm") or "/prpc/CreateVm?json")
    info_url = base + (routes.get("GetInfo") or "/prpc/GetInfo?json")
    remove_url = base + (routes.get("RemoveVm") or "/prpc/RemoveVm?json")
    run_path = pathlib.Path(vmm["run_path"])
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

    def request_for(
        label: str, variant: str, key_provider: Any = "tpm"
    ) -> dict[str, Any]:
        request = json.loads(json.dumps(template))
        request["name"] = f"dtest-{nonce}-{label}"
        request["stopped"] = True
        request["simulated_tee"] = variant
        compose = json.loads(request.get("compose_file") or "{}")
        compose["key_provider"] = key_provider
        request["compose_file"] = json.dumps(compose, sort_keys=True)
        return request

    def create_row(variant: str) -> tuple[str, str]:
        code, body = common.call(create_url, request_for(variant, variant), headers)
        value = json.loads(body or b"{}")
        vm_id = value.get("id") if isinstance(value, dict) else None
        if code != 200 or not vm_id:
            raise AssertionError(
                f"{variant} CreateVm returned HTTP {code}: "
                f"{body.decode('utf-8', 'replace')[:200]}"
            )
        return str(vm_id), variant

    try:
        baseline = common.list_ids(case_manifest)
        evidence["baseline_count"] = len(baseline)
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The case-owned VMM was reachable before the run-scoped TPM matrix was created.",
            }
        )

        labels: dict[str, str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(MATRIX)) as pool:
            futures = [pool.submit(create_row, variant) for variant in MATRIX]
            for future in concurrent.futures.as_completed(futures):
                vm_id, variant = future.result()
                created.append(vm_id)
                labels[vm_id] = variant

        observed: dict[str, dict[str, Any]] = {}
        for vm_id, variant in labels.items():
            manifest_path = run_path / vm_id / "vm-manifest.json"
            persisted = json.loads(manifest_path.read_text())
            actual_swtpm = persisted.get("swtpm")
            expected_swtpm = MATRIX[variant]
            if actual_swtpm is not expected_swtpm:
                raise AssertionError(
                    f"{variant} persisted swtpm={actual_swtpm!r}, expected {expected_swtpm}"
                )
            code, body = common.call(info_url, {"id": vm_id}, headers)
            if code != 200:
                raise AssertionError(f"{variant} GetInfo returned HTTP {code}")
            value = json.loads(body or b"{}")
            info = value.get("info") if isinstance(value, dict) else None
            config = info.get("configuration") if isinstance(info, dict) else None
            if not isinstance(config, dict):
                raise AssertionError(f"{variant} GetInfo omitted configuration")
            compose = json.loads(config.get("compose_file") or "{}")
            if (
                config.get("simulated_tee") != variant
                or compose.get("key_provider") != "tpm"
            ):
                raise AssertionError(
                    f"{variant} GetInfo did not preserve the deployment input"
                )
            observed[variant] = {
                "swtpm": actual_swtpm,
                "simulated_tee": config.get("simulated_tee"),
                "key_provider": compose.get("key_provider"),
                "manifest_present": manifest_path.is_file(),
            }
        if set(common.list_ids(case_manifest)) != baseline | set(created):
            raise AssertionError("TPM matrix did not remain case-scoped")
        evidence["matrix"] = observed
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Five TPM-provider simulator rows persisted the expected swtpm decisions and public inputs independently.",
            }
        )

        invalid_request = request_for(
            "invalid-provider", MATRIX.keys().__iter__().__next__(), 7
        )
        code, _ = common.call(create_url, invalid_request, headers)
        if code < 400:
            raise AssertionError(f"numeric key_provider returned HTTP {code}")
        if set(common.list_ids(case_manifest)) != baseline | set(created):
            raise AssertionError("rejected key provider left partial VM state")
        evidence["negative"] = {
            "numeric_key_provider_http": code,
            "no_partial_state": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "An invalid key provider was rejected without partial state or cross-instance mutation.",
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
            code, _ = common.call(remove_url, {"id": vm_id}, headers)
            statuses.append(code)
        deadline = time.monotonic() + 30
        while (
            set(created) & common.list_ids(case_manifest)
            and time.monotonic() < deadline
        ):
            time.sleep(1)
        all_absent = not bool(set(created) & common.list_ids(case_manifest))
        evidence["cleanup"] = {
            "http_statuses": sorted(statuses),
            "all_absent": all_absent,
        }
        if (
            any(code != 200 for code in statuses) or not all_absent
        ) and failure is None:
            failure = "cleanup failed to remove every TPM matrix VM"

    artifact = {
        "path": "artifacts/swtpm-decision-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Deployment-time swtpm decision matrix",
        "description": "Records persisted TPM decisions, public inputs, rejection isolation, and cleanup.",
    }
    common.atomic_json(result_dir / artifact["path"], evidence)
    common.atomic_json(
        result_dir / "artifacts/manifest.json", {"artifacts": [artifact]}
    )
    status = "PASS" if failure is None else "FAIL"
    common.atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": (
                "TPM attachment decisions were materialized correctly for every simulated platform."
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
