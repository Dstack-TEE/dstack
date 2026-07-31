#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway node URL and status administration across a cluster."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import time
from typing import Any

CASE_ID = "tc-gw-cluster-ad-003"


def load_support() -> Any:
    """Load bounded Gateway HTTP and artifact helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_node_admin_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def decoded(body: bytes) -> dict[str, Any]:
    """Decode a JSON response without retaining native bytes."""
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        return {}


def rpc(node: dict[str, Any], token: str, method: str, value: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Call one authenticated admin method."""
    code, body = SUPPORT.rpc(str(node["admin_url"]).rstrip("/"), token, method, value)
    return code, decoded(body)


def wait_status(nodes: list[dict[str, Any]], token: str, target: int, expected: str) -> bool:
    """Wait until every cluster node reports the expected replicated status."""
    for _ in range(40):
        matched = True
        for node in nodes:
            code, body = rpc(node, token, "Admin.GetNodeStatuses", {})
            statuses = {int(row.get("node_id", 0)): row.get("status") for row in body.get("statuses", [])}
            if code != 200 or statuses.get(target) != expected:
                matched = False
                break
        if matched:
            return True
        time.sleep(0.25)
    return False


def main() -> int:
    """Run canonical URL, replicated status, invalid input, and restoration checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    cluster = manifest["values"]["gateway_cluster"]
    nodes = list(cluster["nodes"])
    token = pathlib.Path(cluster["admin_auth_token_file"]).read_text().strip()
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "Gateway node administration did not complete"
    target_id: int | None = None
    restored = False
    try:
        snapshots = []
        for node in nodes:
            code, body = rpc(node, token, "Admin.Status", {})
            if code != 200:
                raise AssertionError(f"Admin.Status returned HTTP {code}")
            snapshots.append(body)
        ids = [int(row.get("id", 0)) for row in snapshots]
        urls = [str(row.get("url", "")) for row in snapshots]
        checks["stable_unique_identity"] = len(ids) == len(nodes) == len(set(ids)) and all(urls)
        controller = nodes[0]
        target_id = ids[1]
        target_url = urls[1]
        set_url_code = rpc(controller, token, "Admin.SetNodeUrl", {"id": target_id, "url": target_url})[0]
        checks["canonical_url_idempotent"] = set_url_code == 200

        down_code = rpc(controller, token, "Admin.SetNodeStatus", {"id": target_id, "status": "down"})[0]
        down_converged = down_code == 200 and wait_status(nodes, token, target_id, "down")
        up_code = rpc(controller, token, "Admin.SetNodeStatus", {"id": target_id, "status": "up"})[0]
        up_converged = up_code == 200 and wait_status(nodes, token, target_id, "up")
        restored = up_converged
        checks["status_converges_and_restores"] = down_converged and up_converged

        invalid_status_code = rpc(
            controller, token, "Admin.SetNodeStatus", {"id": target_id, "status": "invalid"}
        )[0]
        malformed_url_code = rpc(
            controller, token, "Admin.SetNodeUrl", {"id": target_id, "url": "not-a-sync-url"}
        )[0]
        # Always restore the canonical URL, including after an unexpectedly accepted mutation.
        restore_url_code = rpc(
            controller, token, "Admin.SetNodeUrl", {"id": target_id, "url": target_url}
        )[0]
        checks["invalid_status_rejected"] = invalid_status_code >= 400
        checks["malformed_url_rejected"] = malformed_url_code >= 400
        checks["canonical_url_restored"] = restore_url_code == 200
        checks["post_rejection_state_intact"] = wait_status(nodes, token, target_id, "up")

        if not all(checks.values()):
            raise AssertionError(
                f"node admin checks failed: {sorted(k for k, value in checks.items() if not value)}"
            )
        steps = [
            {"id": f"{CASE_ID}-step-01", "status": "PASS", "observed": "All three nodes exposed unique stable identities and canonical sync URLs."},
            {"id": f"{CASE_ID}-step-02", "status": "PASS", "observed": "Peer down/up state converged across the cluster and the canonical URL update was idempotent."},
            {"id": f"{CASE_ID}-step-03", "status": "PASS", "observed": "Invalid status and malformed URL mutations were rejected without damaging the restored cluster state."},
        ]
        observation = {
            "checks": checks,
            "node_count": len(nodes),
            "unique_node_ids": len(set(ids)),
            "set_url_http": set_url_code,
            "set_down_http": down_code,
            "set_up_http": up_code,
            "invalid_status_http": invalid_status_code,
            "malformed_url_http": malformed_url_code,
            "restore_url_http": restore_url_code,
        }
        path = result_dir / "artifacts/gateway-node-admin.json"
        SUPPORT.atomic_json(path, observation)
        artifacts.append({
            "path": "artifacts/gateway-node-admin.json",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Cluster node administration matrix",
            "description": "Counts, HTTP statuses, and boolean convergence assertions only; no URLs or credentials are retained.",
        })
        status = "PASS"
        summary = "Gateway canonical node URL, replicated status transitions, invalid-input rejection, and restoration passed."
    except Exception as error:  # noqa: BLE001
        if target_id is not None and not restored:
            try:
                rpc(nodes[0], token, "Admin.SetNodeStatus", {"id": target_id, "status": "up"})
            except Exception:  # noqa: BLE001
                pass
        failed = len(steps) + 1
        for index in range(failed, 4):
            steps.append({"id": f"{CASE_ID}-step-{index:02d}", "status": "FAIL" if index == failed else "NOT_RUN", "observed": str(error) if index == failed else "Not run after failure."})
        summary = f"Gateway node administration failed: {error}"
    SUPPORT.atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    SUPPORT.atomic_json(result_dir / "result.json", {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": steps,
        "artifacts": artifacts,
        "remarks": "No admin credential, node URL, certificate, or response body is retained.",
    })
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
