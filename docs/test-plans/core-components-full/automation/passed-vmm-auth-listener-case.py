#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Verify VMM HTTP authentication and private Host API listener separation."""

from __future__ import annotations

import json
import os
import pathlib
import secrets
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-vmm-configurat-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = pathlib.Path(handle.name)
    temporary.replace(path)


def request(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Perform a bounded request and return only response data."""
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return int(response.status), dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), dict(error.headers.items()), error.read()


def structure(body: bytes) -> dict[str, Any]:
    """Describe a response without retaining potentially sensitive values."""
    try:
        value = json.loads(body or b"null")
    except json.JSONDecodeError:
        return {"kind": "text", "nonempty": bool(body)}
    if isinstance(value, dict):
        return {"kind": "object", "keys": sorted(value)}
    if isinstance(value, list):
        return {"kind": "array", "length": len(value)}
    return {"kind": type(value).__name__}


def list_ids(vmm: dict[str, Any]) -> set[str]:
    """List VM work directories inside the case-owned VMM run path."""
    run_path = pathlib.Path(vmm["run_path"])
    return {entry.name for entry in run_path.iterdir() if entry.is_dir()}


def main() -> int:
    """Exercise protected HTTP surfaces and the independent vsock Host API."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    host_api = manifest["values"]["host_api"]
    auth = vmm.get("auth") or {}
    if vmm.get("case_owned") is not True or host_api.get("case_owned") is not True:
        raise RuntimeError("VMM or Host API fixture is not case-owned")
    if auth.get("enabled") is not True or not auth.get("token_file"):
        raise RuntimeError("fixture did not enable VMM authentication")
    token_file = pathlib.Path(auth["token_file"])
    if token_file.stat().st_mode & 0o077:
        raise RuntimeError("VMM token file is accessible outside its owner")
    token = token_file.read_text().strip()
    if not token:
        raise RuntimeError("VMM token file is empty")
    valid = {"Authorization": f"Bearer {token}"}
    wrong = {"Authorization": f"Bearer {secrets.token_hex(32)}"}
    stale = {"X-Admin-Token": secrets.token_hex(32)}
    base = str(vmm["rpc_url"]).rstrip("/")
    version_path = (vmm.get("json_prpc_routes") or {}).get("Version")
    if not version_path:
        raise RuntimeError("fixture omitted the VMM Version route")

    evidence: dict[str, Any] = {
        "token_file_mode": oct(token_file.stat().st_mode & 0o777),
        "token_fingerprint_recorded": False,
    }
    steps: list[dict[str, str]] = []
    failure: str | None = None

    try:
        baseline = list_ids(vmm)
        code, response_headers, body = request(
            base + version_path,
            method="POST",
            body=b"{}",
            headers=valid,
        )
        if code != 200:
            raise AssertionError(f"authenticated Version returned HTTP {code}")
        evidence["baseline"] = {
            "version_http": code,
            "version_structure": structure(body),
            "app_version_header_present": any(
                key.lower() == "x-app-version" for key in response_headers
            ),
            "vm_count": len(baseline),
        }
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The authenticated case-owned VMM was healthy and its VM baseline was recorded.",
            }
        )

        protected: dict[str, dict[str, int]] = {}
        surfaces = {
            "version": (version_path, "POST", b"{}"),
            "ui": ("/", "GET", None),
            "resource": ("/res/x25519.js", "GET", None),
            "logs": ("/logs?id=missing&follow=false&ansi=false&lines=1", "GET", None),
        }
        for name, (path, method, payload) in surfaces.items():
            outcomes: dict[str, int] = {}
            for credential, headers in (
                ("valid", valid),
                ("missing", {}),
                ("wrong", wrong),
                ("stale", stale),
            ):
                status, _, _ = request(
                    base + path, method=method, body=payload, headers=headers
                )
                outcomes[credential] = status
            if outcomes["valid"] != 200:
                raise AssertionError(f"{name} rejected valid credentials: {outcomes}")
            if any(outcomes[key] != 401 for key in ("missing", "wrong", "stale")):
                raise AssertionError(f"{name} accepted invalid credentials: {outcomes}")
            protected[name] = outcomes

        query_status, _, query_body = request(base + "/?token=" + token)
        if query_status != 200:
            raise AssertionError(
                f"GET query-token compatibility returned HTTP {query_status}"
            )
        external_host_status, _, external_host_body = request(
            base + host_api["json_prpc_routes"]["Info"],
            method="POST",
            body=b"{}",
            headers=valid,
        )
        if external_host_status != 404:
            raise AssertionError(
                f"HostApi.Info was exposed on external HTTP with status {external_host_status}"
            )
        evidence["http_matrix"] = protected
        evidence["query_token"] = {
            "http": query_status,
            "structure": structure(query_body),
            "token_persisted": False,
        }
        evidence["external_host_api"] = {
            "http": external_host_status,
            "structure": structure(external_host_body),
            "expected": "not mounted",
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "VMM, UI, resource, and log surfaces enforced authentication while HostApi.Info was absent from external HTTP.",
            }
        )

        private = subprocess.run(
            host_api["commands"]["info"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if private.returncode:
            raise AssertionError(f"private HostApi.Info exited {private.returncode}")
        private_value = json.loads(private.stdout or "{}")
        recovery_status, _, recovery_body = request(
            base + version_path,
            method="POST",
            body=b"{}",
            headers=valid,
        )
        if recovery_status != 200 or list_ids(vmm) != baseline:
            raise AssertionError("authenticated recovery or state isolation failed")
        log_text = pathlib.Path(vmm["log"]).read_text(errors="replace")
        evidence["private_host_api"] = {
            "transport": host_api.get("transport"),
            "exit": private.returncode,
            "structure": structure(json.dumps(private_value).encode()),
        }
        evidence["recovery"] = {
            "version_http": recovery_status,
            "version_structure": structure(recovery_body),
            "vm_baseline_unchanged": True,
            "vmm_process_alive": pathlib.Path(f"/proc/{vmm['pid']}").exists(),
            "log_nonempty": bool(log_text),
            "credential_material_recorded": False,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Private vsock HostApi.Info remained healthy and authenticated VMM service recovered with unchanged state after rejection probes.",
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
        "path": "artifacts/vmm-auth-listener-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "VMM authentication and listener matrix",
        "description": "Records status codes and response structures without credential material.",
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
                "External VMM surfaces enforced authentication and Host API remained private to vsock."
                if status == "PASS"
                else failure
            ),
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Credentials were read only into memory and no mutating VMM operation was performed.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
