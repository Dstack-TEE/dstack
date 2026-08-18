#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise WaveKV encoding, persistence, watch, and live cluster visibility."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path

CASE_ID = "tc-gw-kv-009"


def rpc(url: str, method: str) -> tuple[int, dict[str, object]]:
    """Call one case-owned debug RPC and decode its bounded JSON response."""
    request = urllib.request.Request(
        f"{url.rstrip('/')}/{method}",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read(1024 * 1024)
            return response.status, json.loads(body) if body else {}
    except Exception:  # noqa: BLE001
        return 599, {}


def main() -> int:
    """Run deterministic KV branches and observe the live three-node cluster."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    cluster = manifest["values"]["gateway_cluster"]
    nodes = cluster["nodes"]
    snapshots = [rpc(str(node["debug_url"]), "Debug.GetSyncData") for node in nodes]
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    unit = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "dstack-gateway",
            "kv::",
            "--",
            "--nocapture",
        ],
        cwd=Path(runtime["repository"]) / "dstack",
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    output = unit.stdout + unit.stderr
    unit_passed = max(
        (int(value) for value in re.findall(r"(\d+) passed; 0 failed", output)),
        default=0,
    )
    peer_counts = [
        len(body.get("peer_addrs", body.get("peerAddrs", [])))
        for code, body in snapshots
        if code == 200
    ]
    node_counts = [
        len(body.get("nodes", [])) for code, body in snapshots if code == 200
    ]
    checks = {
        "case_owned_cluster": len(nodes) == 3,
        "all_debug_snapshots": len(snapshots) == 3
        and all(code == 200 for code, _ in snapshots),
        "cluster_node_visibility": len(node_counts) == 3
        and all(count >= 3 for count in node_counts),
        "cluster_peer_visibility": len(peer_counts) == 3
        and all(count >= 2 for count in peer_counts),
        "kv_lifecycle_matrix": unit.returncode == 0 and unit_passed >= 5,
    }
    passed = all(checks.values())
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "checks": checks,
        "cluster_node_count": len(nodes),
        "visible_node_counts": node_counts,
        "visible_peer_counts": peer_counts,
        "unit_passed": unit_passed,
        "unit_returncode": unit.returncode,
        "retained_values_or_endpoints": False,
    }
    artifact = result_dir / "artifacts/gateway-kv-lifecycle.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        "WaveKV key, corruption, watch, persistence, ephemeral, tombstone, and cluster visibility checks passed."
        if passed
        else f"WaveKV checks failed: {sorted(k for k, value in checks.items() if not value)}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {
                "id": f"{CASE_ID}-step-{n:02d}",
                "status": status,
                "observed": observed,
            }
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/gateway-kv-lifecycle.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "A live case-owned three-node Gateway cluster provides sync visibility while the source-defined storage branches use isolated temporary persistent and ephemeral stores. Evidence retains counts and booleans only.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
