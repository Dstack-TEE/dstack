#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic harness for the VMM host API, which listens on AF_VSOCK.

The host API is not reachable over TCP like the VMM RPC listener: it answers on
vsock CID 2 at a lease-allocated port. The fixture publishes that endpoint and
its routes under `host_api`, and `automation/vsock-http.py` performs one bounded
request against it.

Each case checks that the documented response fields are present, that an
unknown route is refused, and that an unknown request field is ignored rather
than rejected.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

# case_id -> (method, deterministic, request payload or None for an empty body)
CASES: dict[str, tuple[str, bool, dict[str, Any] | None]] = {
    "tc-vmm-hostapi-001": ("Info", False, None),
    # HostApi.Notify and HostApi.GetSealingKey are not reachable from here.
    # notify resolves the reporting VM from the caller's vsock CID, so a
    # host-side request maps to no VM and returns HTTP 400; GetSealingKey needs
    # a quote only a guest can produce. Both need a running guest to originate
    # the call, not a harness dialling the host API.
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON so a reader never observes a partial document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, delete=False, encoding="utf-8"
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = handle.name
    os.replace(temporary, path)


def inventory_entry(plan_root: pathlib.Path, method: str) -> dict[str, Any]:
    """Load the authoritative HostApi contract for the method."""
    document = json.loads((plan_root / "catalog" / "api-inventory.json").read_text())
    matches: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("service") == "HostApi" and value.get("method") == method:
                matches.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    if len(matches) != 1:
        raise RuntimeError(f"expected one inventory entry for HostApi.{method}")
    return matches[0]


def vsock_call(
    plan_root: pathlib.Path,
    endpoint: dict[str, Any],
    path: str,
    body: str,
    public: bool = False,
) -> dict[str, Any]:
    """Perform one bounded host-API request and return its structural result."""
    argv = [
        "/usr/bin/python3",
        str(plan_root / "shared" / "automation" / "vsock-http.py"),
        "--cid",
        str(endpoint.get("cid", 2)),
        "--port",
        str(endpoint["port"]),
        "--path",
        path,
        "--body",
        body,
    ]
    if public:
        argv.append("--public-json")
    process = subprocess.run(
        argv, capture_output=True, text=True, timeout=60, check=False
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"host-api request to {path} failed with {process.returncode}: "
            f"{process.stderr[-400:]}"
        )
    return json.loads(process.stdout)


def main() -> int:
    """Run the host-API case selected by the environment."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    if case_id not in CASES:
        raise SystemExit(f"unsupported host-api case: {case_id}")
    method, deterministic, payload = CASES[case_id]
    request_payload = payload if payload is not None else {}
    request_json = json.dumps(request_payload)

    endpoint = (manifest["values"].get("host_api") or {}).copy()
    if not endpoint.get("port"):
        raise SystemExit("fixture publishes no host_api endpoint")
    route = (endpoint.get("json_prpc_routes") or {}).get(
        method
    ) or f"/api/{method}?json"

    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, Any]] = []
    status, failure = "PASS", None
    contract: dict[str, Any] = {"case_id": case_id, "method": method, "route": route}

    try:
        step = f"{case_id}-step-01"
        print(f"STEP {step} START", flush=True)
        entry = inventory_entry(plan_root, method)
        baseline = vsock_call(plan_root, endpoint, route, request_json)
        contract["baseline"] = baseline
        if baseline["status"] != 200:
            raise AssertionError(f"baseline request returned HTTP {baseline['status']}")
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "The lease-owned host-API vsock listener answered the "
                "documented route.",
            }
        )
        print(f"EVIDENCE {step} - Proves the vsock listener is reachable.", flush=True)
        print(json.dumps(baseline, sort_keys=True), flush=True)
        print(f"STEP {step} END - PASS", flush=True)

        step = f"{case_id}-step-02"
        print(f"STEP {step} START", flush=True)
        valid = vsock_call(plan_root, endpoint, route, request_json, public=True)
        if valid["status"] != 200:
            raise AssertionError(f"valid request returned HTTP {valid['status']}")
        value = valid.get("json")
        if not isinstance(value, dict):
            raise AssertionError("response was not a JSON object")
        missing = sorted(
            {field["name"] for field in entry["response_fields"]} - set(value)
        )
        if missing:
            raise AssertionError(f"response omitted documented fields: {missing}")
        unknown_route = vsock_call(
            plan_root, endpoint, route.replace(method, method + "NoSuch"), request_json
        )
        if unknown_route["status"] < 400:
            raise AssertionError(
                f"unknown route accepted with HTTP {unknown_route['status']}"
            )
        extraneous = vsock_call(
            plan_root,
            endpoint,
            route,
            json.dumps({**request_payload, "__probe": True}),
        )
        if extraneous["status"] != 200:
            raise AssertionError(
                f"unknown-field request rejected with HTTP {extraneous['status']}"
            )
        contract["valid_keys"] = sorted(value)
        contract["unknown_route"] = unknown_route
        contract["extraneous"] = extraneous
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "Every documented response field was present, an "
                "unknown route was refused, and an unknown request field was "
                "ignored.",
            }
        )
        print(
            f"EVIDENCE {step} - Proves the documented response contract and "
            "input handling.",
            flush=True,
        )
        print(json.dumps(contract["valid_keys"], sort_keys=True), flush=True)
        print(f"STEP {step} END - PASS", flush=True)

        step = f"{case_id}-step-03"
        print(f"STEP {step} START", flush=True)
        repeat = vsock_call(plan_root, endpoint, route, request_json)
        if repeat["status"] != 200:
            raise AssertionError(f"repeat request returned HTTP {repeat['status']}")
        if deterministic and repeat["body_sha256"] != baseline["body_sha256"]:
            raise AssertionError(
                "documented deterministic response changed across identical requests"
            )
        contract["repeat"] = repeat
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "The listener stayed available and repeat behaviour "
                "matched the documented determinism policy.",
            }
        )
        print(f"EVIDENCE {step} - Proves post-error availability.", flush=True)
        print(json.dumps(repeat, sort_keys=True), flush=True)
        print(f"STEP {step} END - PASS", flush=True)
    except Exception as error:  # noqa: BLE001 - recorded as a case failure
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        done = {item["id"] for item in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in done:
                steps.append({"id": step_id, "status": "FAIL", "observed": failure})

    contract["status"] = status
    contract["failure"] = failure
    atomic_json(artifacts / "host-api-contract.json", contract)
    artifact = {
        "name": "Host API contract",
        "path": "artifacts/host-api-contract.json",
        "step_id": f"{case_id}-step-02",
        "description": (
            "Records the vsock endpoint, documented response fields, unknown "
            "route rejection and unknown field handling."
        ),
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": (
                f"HostApi.{method} answered over vsock with every documented "
                "field, refused an unknown route and ignored an unknown field."
            )
            if status == "PASS"
            else failure,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Exercises the host API over its AF_VSOCK transport.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
