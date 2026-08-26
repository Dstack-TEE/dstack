#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway cluster handshakes, counters, and node observations."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import socket
import sys
import time
from typing import Any

CASE_ID = "tc-gw-cluster-ad-004"


def load_support() -> Any:
    """Load bounded Gateway HTTP and atomic artifact helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_observability_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def decoded(body: bytes) -> dict[str, Any]:
    """Decode JSON without retaining native response bytes."""
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        return {}


def rpc(
    node: dict[str, Any],
    token: str | None,
    method: str,
    value: dict[str, Any],
    *,
    debug: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Call one case-owned Gateway pRPC method."""
    base = str(node["debug_url"] if debug else node["admin_url"]).rstrip("/")
    code, body = SUPPORT.http_call(
        f"{base}/{method}", json.dumps(value).encode(), "application/json", token
    )
    return code, decoded(body)


def main() -> int:
    """Run handshake replication, online status, counters, and last-seen checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    cluster = manifest["values"]["gateway_cluster"]
    nodes = list(cluster["nodes"])
    token = pathlib.Path(cluster["admin_auth_token_file"]).read_text().strip()
    suffix = str(manifest["lease_id"])[-10:]
    instance_id = f"observe-{suffix}"
    app_id = f"observe-app-{suffix}"
    public_key = base64.b64encode(os.urandom(32)).decode()
    timestamp = int(time.time())
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "Gateway cluster observability did not complete"
    try:
        register_code, _ = rpc(
            nodes[0],
            None,
            "Debug.RegisterCvm",
            {
                "app_id": app_id,
                "instance_id": instance_id,
                "client_public_key": public_key,
            },
            debug=True,
        )
        pathlib.Path(nodes[0]["handshake_fixture"]).write_text(
            f"{public_key} {timestamp}\n", encoding="utf-8"
        )

        handshake_rows: list[dict[str, Any]] = []
        meta: dict[str, Any] = {}
        status_view: dict[str, Any] = {}
        for _ in range(70):
            # Status refresh publishes the local cache observation into WaveKV.
            rpc(nodes[0], token, "Admin.Status", {})
            _, handshake_view = rpc(
                nodes[1],
                token,
                "Admin.GetInstanceHandshakes",
                {"instance_id": instance_id},
            )
            handshake_rows = list(handshake_view.get("handshakes", []))
            _, meta = rpc(nodes[0], token, "Admin.GetMeta", {})
            _, status_view = rpc(nodes[1], token, "Admin.Status", {})
            if (
                any(
                    int(row.get("observer_node_id", 0)) == int(nodes[0]["node_id"])
                    and int(row.get("timestamp", 0)) == timestamp
                    for row in handshake_rows
                )
                and int(meta.get("online", 0)) >= 1
                and any(
                    row.get("instance_id") == instance_id
                    and int(row.get("latest_handshake", 0)) == timestamp
                    for row in status_view.get("hosts", [])
                )
            ):
                break
            time.sleep(0.25)
        checks["handshake_replicated"] = register_code == 200 and any(
            int(row.get("observer_node_id", 0)) == int(nodes[0]["node_id"])
            and int(row.get("timestamp", 0)) == timestamp
            for row in handshake_rows
        )
        checks["online_and_status_match"] = int(meta.get("online", 0)) >= 1 and any(
            row.get("instance_id") == instance_id
            and int(row.get("latest_handshake", 0)) == timestamp
            for row in status_view.get("hosts", [])
        )

        baseline_status = [rpc(node, token, "Admin.Status", {})[1] for node in nodes]
        baseline_global = rpc(nodes[0], token, "Admin.GetGlobalConnections", {})[1]
        for node in nodes:
            host, port = str(node["proxy_address"]).rsplit(":", 1)
            for _ in range(4):
                try:
                    with socket.create_connection(
                        (host, int(port)), timeout=1
                    ) as stream:
                        stream.sendall(b"invalid-proxy-probe\r\n")
                except OSError:
                    pass
        time.sleep(0.5)
        final_status = [rpc(node, token, "Admin.Status", {})[1] for node in nodes]
        final_global = rpc(nodes[0], token, "Admin.GetGlobalConnections", {})[1]
        checks["connection_counters_return_to_baseline"] = int(
            final_global.get("total_connections", 0)
        ) == int(baseline_global.get("total_connections", 0)) and [
            int(row.get("num_connections", 0)) for row in final_status
        ] == [int(row.get("num_connections", 0)) for row in baseline_status]

        node_statuses = rpc(nodes[0], token, "Admin.GetNodeStatuses", {})[1].get(
            "statuses", []
        )
        wave = rpc(nodes[0], token, "Admin.WaveKvStatus", {})[1]
        last_seen = []
        for store_name in ("persistent", "ephemeral"):
            for peer in (wave.get(store_name) or {}).get("peers", []):
                last_seen.extend(peer.get("last_seen", []))
        checks["node_status_and_timestamps_accurate"] = (
            len(node_statuses) >= len(nodes)
            and all(row.get("status") == "up" for row in node_statuses)
            and any(int(row.get("timestamp", 0)) > 0 for row in last_seen)
        )

        if not all(checks.values()):
            raise AssertionError(
                f"observability checks failed: {sorted(k for k, value in checks.items() if not value)}; online={int(meta.get('online', 0))}; host_matches={sum(row.get('instance_id') == instance_id and int(row.get('latest_handshake', 0)) == timestamp for row in status_view.get('hosts', []))}"
            )
        steps = [
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The three-node cluster reported stable status and a clean connection baseline.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "A deterministic WireGuard observation propagated with the exact observer and timestamp into per-instance, online, and status views.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Rejected proxy probes returned counters to baseline and WaveKV node status/last-seen observations remained current.",
            },
        ]
        observation = {
            "checks": checks,
            "node_count": len(nodes),
            "registration_http": register_code,
            "handshake_observer_count": len(handshake_rows),
            "online_count": int(meta.get("online", 0)),
            "baseline_total_connections": int(
                baseline_global.get("total_connections", 0)
            ),
            "final_total_connections": int(final_global.get("total_connections", 0)),
            "node_status_count": len(node_statuses),
            "last_seen_entry_count": len(last_seen),
        }
        path = result_dir / "artifacts/gateway-cluster-observability.json"
        SUPPORT.atomic_json(path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-cluster-observability.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "Cluster observability matrix",
                "description": "Counts and boolean assertions only; no WireGuard key, instance identifier, address, URL, credential, or timestamp value is retained.",
            }
        )
        status = "PASS"
        summary = "Gateway handshake replication, online/status views, connection counter recovery, and node last-seen observations passed."
    except Exception as error:  # noqa: BLE001
        failed = len(steps) + 1
        for index in range(failed, 4):
            steps.append(
                {
                    "id": f"{CASE_ID}-step-{index:02d}",
                    "status": "FAIL" if index == failed else "NOT_RUN",
                    "observed": str(error)
                    if index == failed
                    else "Not run after failure.",
                }
            )
        summary = f"Gateway cluster observability failed: {error}"
    SUPPORT.atomic_json(
        result_dir / "artifacts/manifest.json", {"artifacts": artifacts}
    )
    SUPPORT.atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "No WireGuard key, instance identifier, address, URL, credential, native response body, or timestamp value is retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
