#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway health dashboard and graceful persistent exit."""

from __future__ import annotations

import base64
import html
import importlib.util
import json
import os
import pathlib
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-gw-cluster-ad-007"


def load_support() -> Any:
    """Load bounded HTTP and atomic artifact helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_exit_support", path)
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


def rpc(
    base: str, token: str | None, method: str, value: dict[str, Any]
) -> tuple[int | None, bytes]:
    """Call a bounded pRPC method and classify shutdown transport closure."""
    try:
        return SUPPORT.http_call(
            f"{base.rstrip(chr(47))}/{method}",
            json.dumps(value).encode(),
            "application/json",
            token,
        )
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
        return None, b""


def get(url: str, token: str) -> tuple[int, bytes]:
    """Read an authenticated admin page."""
    request = urllib.request.Request(url, method="GET")
    request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(
            request, timeout=5, context=ssl._create_unverified_context()
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def wait_process_exit(pid: int) -> bool:
    """Wait for a process to disappear."""
    for _ in range(40):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def wait_port(address: str) -> bool:
    """Wait for a restarted listener."""
    host, port_text = address.rsplit(":", 1)
    for _ in range(60):
        try:
            with socket.create_connection((host, int(port_text)), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> int:
    """Run health, escaping, connection drain, exit, restart, and persistence checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    node = values["gateway_cluster"]["nodes"][-1]
    token = (
        pathlib.Path(values["gateway_cluster"]["admin_auth_token_file"])
        .read_text()
        .strip()
    )
    admin = str(node["admin_url"]).rstrip("/")
    debug = str(node["debug_url"]).rstrip("/")
    proxy_address = str(node["proxy_address"])
    instance_id = f"<script>exit-{str(manifest.get('lease_id'))[-8:]}</script>"
    app_id = "health-exit-case"
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "Gateway health and exit lifecycle did not complete"
    restarted: subprocess.Popen[bytes] | None = None
    held: socket.socket | None = None
    try:
        health_code, _ = get(str(node["health_url"]), token)
        register_code, _ = rpc(
            debug,
            None,
            "Debug.RegisterCvm",
            {
                "app_id": app_id,
                "instance_id": instance_id,
                "client_public_key": base64.b64encode(os.urandom(32)).decode(),
            },
        )
        dashboard_code, dashboard = get(str(node["dashboard_url"]), token)
        raw = instance_id.encode()
        escaped = html.escape(instance_id).encode()
        dashboard_lower = dashboard.lower()
        encoded_sentinel = any(
            marker in dashboard_lower
            for marker in (
                b"&lt;script&gt;",
                b"&#x3c;script&#x3e;",
                b"&#60;script&#62;",
            )
        )
        checks["health_and_dashboard_available"] = (
            health_code == 200 and dashboard_code == 200
        )
        checks["dashboard_escapes_state"] = (
            raw not in dashboard
            and (escaped in dashboard or encoded_sentinel)
            and app_id.encode() in dashboard
        )

        held = socket.create_connection(
            (proxy_address.rsplit(":", 1)[0], int(proxy_address.rsplit(":", 1)[1])),
            timeout=3,
        )
        exit_code, _ = rpc(admin, token, "Admin.Exit", {})
        exited = wait_process_exit(int(node["pid"]))
        held.settimeout(2)
        try:
            drained = held.recv(1) == b""
        except (ConnectionError, OSError, TimeoutError):
            drained = True
        held.close()
        held = None
        checks["graceful_exit"] = exit_code in {None, 200} and exited and drained

        binary = str(manifest["values"]["prepared_binaries"]["dstack_gateway"]["path"])
        guest_socket = str(
            values["gateway_guest_simulator"]["services"]["DstackGuest"]["socket"]
        )
        environment = os.environ.copy()
        environment["DSTACK_AGENT_ADDRESS"] = f"unix:{guest_socket}"
        restarted = subprocess.Popen(
            [binary, "--config", str(node["config"])],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
        ready = wait_port(str(node["rpc_url"]).split("//", 1)[1].split("/", 1)[0])
        sync_code, sync_body = rpc(debug, None, "Debug.GetSyncData", {})
        instances = decoded(sync_body).get("instances", [])
        retained = [
            row
            for row in instances
            if row.get("instance_id") == instance_id and row.get("app_id") == app_id
        ]
        checks["persistent_state_after_restart"] = (
            ready and sync_code == 200 and len(retained) == 1
        )

        if not all(checks.values()):
            raise AssertionError(
                f"health/exit checks failed: {sorted(k for k, value in checks.items() if not value)}; register={register_code}; dashboard_full={b'Dstack Gateway Dashboard' in dashboard}; exit={exit_code}; exited={exited}; drained={drained}; ready={ready}; sync={sync_code}; retained={len(retained)}"
            )
        steps = [
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Authenticated health and dashboard endpoints were available and escaped a run-owned HTML sentinel.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Admin.Exit closed a held proxy connection and terminated the selected cluster node within the bounded deadline.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Restarting the same candidate with its case-owned configuration restored the run-owned synchronized instance exactly once.",
            },
        ]
        observation = {
            "checks": checks,
            "health_http": health_code,
            "dashboard_http": dashboard_code,
            "registration_http": register_code,
            "exit_http": exit_code,
            "process_exited": exited,
            "held_connection_drained": drained,
            "restart_ready": ready,
            "restart_sync_http": sync_code,
            "retained_match_count": len(retained),
        }
        path = result_dir / "artifacts/gateway-health-exit.json"
        SUPPORT.atomic_json(path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-health-exit.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "Health and graceful exit lifecycle",
                "description": "HTTP statuses, counts, and boolean lifecycle assertions only; no instance value, key, URL, token, or response body is retained.",
            }
        )
        status = "PASS"
        summary = "Gateway health, dashboard escaping, graceful connection drain, process exit, and persistent restart passed."
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
        summary = f"Gateway health and exit lifecycle failed: {error}"
    finally:
        if held is not None:
            held.close()
        if restarted is not None and restarted.poll() is None:
            restarted.send_signal(signal.SIGTERM)
            try:
                restarted.wait(timeout=5)
            except subprocess.TimeoutExpired:
                restarted.kill()
                restarted.wait(timeout=5)
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
            "remarks": "The restarted process was terminated by the harness; no key, instance value, URL, bearer token, or native response body is retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
