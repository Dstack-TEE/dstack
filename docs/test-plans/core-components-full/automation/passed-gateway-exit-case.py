#!/usr/bin/env python3
"""Deterministic four-node lifecycle test for Admin.Exit."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import pathlib
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

VARIANTS = (
    ("json_empty", b"{}", "application/json"),
    ("protobuf_empty", b"", "application/octet-stream"),
    ("extraneous_json", b'{"probe":true}', "application/json"),
    ("malformed_protobuf", bytes((0x0A, 0xFF)), "application/octet-stream"),
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def call(url: str, body: bytes, content_type: str, token: str | None) -> dict[str, Any]:
    """Call one admin route without persisting its bearer credential."""
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(
            request, timeout=10, context=ssl._create_unverified_context()
        ) as response:
            raw = response.read()
            status = int(response.status)
            response_type = response.headers.get("Content-Type")
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = int(error.code)
        response_type = error.headers.get("Content-Type") if error.headers else None
    except (
        urllib.error.URLError,
        TimeoutError,
        ConnectionError,
        ConnectionResetError,
        http.client.RemoteDisconnected,
    ):
        raw = b""
        status = 0
        response_type = None
    parsed: Any = None
    if raw:
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return {
        "status": status,
        "body": parsed,
        "body_len": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "content_type": response_type,
    }


def endpoint_ready(url: str) -> bool:
    """Return whether the URL's TCP listener accepts a connection."""
    parsed = urllib.parse.urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection(
            (parsed.hostname or "127.0.0.1", port), timeout=1
        ):
            return True
    except OSError:
        return False


def wait_stopped(url: str, timeout: float = 8.0) -> float:
    """Wait for an Exit target to stop accepting connections."""
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if not endpoint_ready(url):
            return round(time.monotonic() - started, 3)
        time.sleep(0.1)
    raise AssertionError(
        "Admin.Exit target still accepted connections after its deadline"
    )


def main() -> int:
    """Execute Admin.Exit on four independent lease-owned Gateway nodes."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != "tc-gw-admin-003":
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    cluster = manifest["values"].get("gateway_cluster") or {}
    nodes = list(cluster.get("nodes") or [])
    if manifest.get("profile") != "gateway-exit-cluster" or len(nodes) != 4:
        raise RuntimeError("gateway-exit-cluster did not provide exactly four nodes")
    steps: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    status = "PASS"
    failure = ""

    def token(node: dict[str, Any]) -> str:
        value = pathlib.Path(node["admin_auth_token_file"]).read_text().strip()
        if not value:
            raise RuntimeError("prepared admin token was empty")
        return value

    def record(name: str, step_id: str, value: Any, description: str) -> None:
        atomic_json(artifacts_dir / name, value)
        artifacts.append(
            {
                "path": f"artifacts/{name}",
                "step_id": step_id,
                "name": name,
                "description": description,
            }
        )

    try:
        step = f"{case_id}-step-01"
        print(f"STEP {step} START", flush=True)
        prerequisite: list[dict[str, Any]] = []
        for index, node in enumerate(nodes):
            base = str(node["admin_url"]).rstrip("/")
            authorization = token(node)
            info = call(
                base + "/Admin.GetInfo", b"{}", "application/json", authorization
            )
            unauthorized = call(base + "/Admin.Exit", b"{}", "application/json", None)
            if info["status"] != 200 or unauthorized["status"] < 400:
                raise AssertionError(
                    f"node {index} baseline or authorization enforcement failed"
                )
            if not endpoint_ready(base):
                raise AssertionError(f"unauthorized Exit stopped node {index}")
            prerequisite.append(
                {
                    "node_index": index,
                    "info_http": info["status"],
                    "unauthorized_exit": unauthorized,
                    "listener_alive_after_rejection": True,
                }
            )
        invalid = call(
            str(nodes[0]["admin_url"]).rstrip("/") + "/Admin.ExitNoSuch",
            b"{}",
            "application/json",
            token(nodes[0]),
        )
        if invalid["status"] < 400 or not endpoint_ready(str(nodes[0]["admin_url"])):
            raise AssertionError("invalid Exit route was accepted or stopped its node")
        prerequisite[0]["invalid_route"] = invalid
        record(
            "step01-prerequisite.json",
            step,
            prerequisite,
            "Four live authenticated nodes plus unauthorized and invalid-route rejection.",
        )
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "Four lease-owned nodes were live; missing authorization and invalid routing were rejected without terminating a node.",
            }
        )
        print(f"STEP {step} END - PASS", flush=True)

        step = f"{case_id}-step-02"
        print(f"STEP {step} START", flush=True)
        lifecycle: list[dict[str, Any]] = []
        record(
            "step02-exit-matrix.json",
            step,
            lifecycle,
            "Each Empty/body-ignore representation returned Empty and stopped only its own node.",
        )
        for index, (name, body, content_type) in enumerate(VARIANTS):
            node = nodes[index]
            base = str(node["admin_url"]).rstrip("/")
            response = call(base + "/Admin.Exit", body, content_type, token(node))
            row = {
                "variant": name,
                "content_type": content_type,
                "response": response,
            }
            lifecycle.append(row)
            atomic_json(artifacts_dir / "step02-exit-matrix.json", lifecycle)
            if response["status"] != 200 or response["body_len"] != 0:
                raise AssertionError(
                    f"{name} did not return the documented Empty response"
                )
            stopped_after = wait_stopped(base)
            survivors = [
                later
                for later in range(index + 1, len(nodes))
                if endpoint_ready(str(nodes[later]["admin_url"]))
            ]
            expected_survivors = list(range(index + 1, len(nodes)))
            if survivors != expected_survivors:
                raise AssertionError(f"{name} affected another cluster node")
            row["stopped_after_seconds"] = stopped_after
            row["remaining_live_node_indexes"] = survivors
            atomic_json(artifacts_dir / "step02-exit-matrix.json", lifecycle)
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "JSON Empty, protobuf Empty, extraneous JSON, and malformed protobuf bytes were body-ignored Empty requests; each stopped exactly its target node.",
            }
        )
        print(f"STEP {step} END - PASS", flush=True)

        step = f"{case_id}-step-03"
        print(f"STEP {step} START", flush=True)
        repeat = call(
            str(nodes[0]["admin_url"]).rstrip("/") + "/Admin.Exit",
            b"{}",
            "application/json",
            token(nodes[0]),
        )
        all_stopped = all(not endpoint_ready(str(node["admin_url"])) for node in nodes)
        diagnostics = []
        for index, node in enumerate(nodes):
            log_path = pathlib.Path(str(node["log"]))
            text = log_path.read_text(errors="replace") if log_path.is_file() else ""
            diagnostics.append(
                {
                    "node_index": index,
                    "log_present": log_path.is_file(),
                    "log_sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "panic_lines": sum(
                        1 for line in text.splitlines() if "panic" in line.lower()
                    ),
                    "content_persisted": False,
                }
            )
        if (
            repeat["status"] != 0
            or not all_stopped
            or any(row["panic_lines"] for row in diagnostics)
        ):
            raise AssertionError(
                "post-Exit isolation, repeat failure, or diagnostics contract failed"
            )
        record(
            "step03-isolation.json",
            step,
            {
                "repeat_after_exit": repeat,
                "all_nodes_stopped": all_stopped,
                "diagnostics": diagnostics,
            },
            "All listeners stayed down, repeat transport failed, and logs contained no panic.",
        )
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "All four listeners remained stopped, repeat invocation failed at transport, and node diagnostics contained no panic.",
            }
        )
        print(f"STEP {step} END - PASS", flush=True)
        summary = "Admin.Exit returned Empty for all generated body-ignore encodings, stopped only each lease-owned target, rejected unauthorized and invalid routes, and left no live node or panic."
    except Exception as error:  # noqa: BLE001
        status = "FAIL"
        failure = str(error)
        summary = f"Admin.Exit failed: {failure}"
        done = {item["id"] for item in steps}
        failed_written = False
        for number in (1, 2, 3):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id in done:
                continue
            steps.append(
                {
                    "id": step_id,
                    "status": "FAIL" if not failed_written else "NOT_RUN",
                    "observed": failure
                    if not failed_written
                    else "Not run after earlier failure.",
                }
            )
            failed_written = True

    atomic_json(artifacts_dir / "manifest.json", {"artifacts": artifacts})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "All processes, listeners, tokens, logs, and effects belong to the fixture lease; credentials and log content are never persisted.",
        },
    )
    print(json.dumps({"status": status, "summary": summary}), flush=True)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
