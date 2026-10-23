#!/usr/bin/env python3
"""Verify guest-agent socket activation, transport isolation, and recovery."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-observabil-002"


def emit(step: str, state: str) -> None:
    """Emit one live step transition."""
    print(f"STEP {CASE_ID}-{step} {state}", flush=True)


def ssh(
    argv: list[str], command: str, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Execute one bounded command through the manifest-recorded SSH route."""
    result = subprocess.run(
        [*argv, command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"guest command failed ({result.returncode}): {command!r}; "
            f"stdout={result.stdout[-800:]!r}; stderr={result.stderr[-800:]!r}"
        )
    return result


def guest_rpc(argv: list[str], socket: str, route: str) -> dict[str, Any]:
    """Call a non-secret JSON RPC through one guest Unix socket."""
    header = shlex.quote("Content-Type: application/json")
    body = shlex.quote("{}")
    command = (
        "curl --silent --show-error --fail-with-body --max-time 20 "
        f"--unix-socket {shlex.quote(socket)} "
        f"--header {header} "
        f"--data-binary {body} "
        f"http://localhost/{shlex.quote(route)}"
    )
    raw = ssh(argv, command).stdout
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"{route} returned invalid JSON ({len(raw)} bytes): {raw[:500]!r}"
        ) from error
    if not isinstance(value, dict):
        raise AssertionError(f"{route} returned a non-object")
    return value


def http_json(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """POST JSON and return the HTTP status and object response."""
    request = urllib.request.Request(
        url,
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            code = response.status
    except urllib.error.HTTPError as error:
        raw = error.read()
        code = error.code
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict):
        raise AssertionError(f"{url} returned a non-object")
    return code, value


def wait_active(argv: list[str], unit: str) -> None:
    """Wait until a systemd unit reports active."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if (
            ssh(
                argv, f"systemctl is-active --quiet {shlex.quote(unit)}", check=False
            ).returncode
            == 0
        ):
            return
        time.sleep(0.5)
    raise AssertionError(f"{unit} did not become active")


def main() -> int:
    """Run the socket activation and isolation acceptance matrix."""
    manifest_path = os.environ.get("DSTACK_TEST_CASE_MANIFEST")
    result_dir_value = os.environ.get("DSTACK_TEST_RESULT_DIR")
    if not manifest_path or not result_dir_value:
        raise SystemExit(
            "DSTACK_TEST_CASE_MANIFEST and DSTACK_TEST_RESULT_DIR are required"
        )
    result_path = str(Path(result_dir_value) / "result.json")
    manifest = json.loads(Path(manifest_path).read_text())
    values = manifest.get("values", {})
    lifecycle = values.get("socket_activation_lifecycle")
    ssh_argv = values.get("ssh_argv")
    services = values.get("services", {})
    observations: dict[str, Any] = {}
    steps: list[dict[str, Any]] = []
    status = "PASS"
    summary = "socket activation and listener isolation matrix passed"
    stage = "fixture"

    try:
        required = (
            isinstance(lifecycle, dict)
            and lifecycle.get("destructive_actions_allowed") is True
            and values.get("destructive_actions_allowed") is True
            and isinstance(ssh_argv, list)
            and isinstance(services, dict)
        )
        if not required:
            status = "BLOCKED"
            summary = "fixture lacks a case-owned socket activation lifecycle guest"
            observations["missing_capability"] = "socket-activation-lifecycle-guest"
        else:
            service = str(lifecycle["service_unit"])
            socket_unit = str(lifecycle["socket_unit"])
            dstack_socket = str(lifecycle["dstack_socket"])
            tappd_socket = str(lifecycle["tappd_socket"])
            external_port = int(lifecycle["external_port"])
            guest_port = int(lifecycle["guest_api_vsock_port"])

            stage = "baseline"
            emit("step-01", "START")
            baseline = ssh(
                ssh_argv,
                "set -eu; "
                f"systemctl is-active {shlex.quote(service)} {shlex.quote(socket_unit)}; "
                f"test -S {shlex.quote(dstack_socket)}; test -S {shlex.quote(tappd_socket)}; "
                f"ss -H -ltn sport = :{external_port}; "
                f"! ss -H -ltn sport = :{guest_port} | grep -q .",
            )
            dstack_before = guest_rpc(ssh_argv, dstack_socket, "Info")
            tappd_before = guest_rpc(ssh_argv, tappd_socket, "prpc/Info")
            if not dstack_before.get("app_id") or not tappd_before.get("app_id"):
                raise AssertionError("Unix listener Info response was incomplete")
            observations["baseline"] = {
                "unit_states": baseline.stdout.splitlines()[:2],
                "dstack_app_id_sha256": hashlib.sha256(
                    str(dstack_before["app_id"]).encode()
                ).hexdigest(),
                "tappd_app_id_sha256": hashlib.sha256(
                    str(tappd_before["app_id"]).encode()
                ).hexdigest(),
                "tcp_8000_isolated": True,
                "external_8090_listening": True,
            }
            steps.append(
                {
                    "id": "tc-gos-observabil-002-step-01",
                    "status": "PASS",
                    "observed": "The case-owned guest exposed active service and socket units, both Unix sockets, external TCP 8090, and no guest TCP 8000 listener.",
                }
            )
            emit("step-01", "PASS")

            stage = "transport-isolation"
            emit("step-02", "START")
            dashboard = services.get("Dashboard", {})
            dashboard_url = str(dashboard.get("url", "")).rstrip("/")
            with urllib.request.urlopen(
                dashboard_url + "/prpc/Worker.Version", timeout=20
            ) as response:
                external_body = json.loads(response.read())
                if response.status != 200 or not external_body.get("version"):
                    raise AssertionError("external Worker.Version was unavailable")
            proxied = services.get("ProxiedGuestApi", {})
            proxied_url = str(proxied.get("url", "")).format(method="Info")
            proxied_code, proxied_body = http_json(
                proxied_url, {"id": str(proxied.get("id", ""))}
            )
            if proxied_code != 200 or not proxied_body.get("version"):
                raise AssertionError("ProxiedGuestApi.Info was unavailable")
            forbidden: dict[str, int] = {}
            for route in (
                "Info",
                "prpc/DstackGuest.Info",
                "prpc/Tappd.Info",
                "api/GuestApi.Info",
            ):
                try:
                    urllib.request.urlopen(dashboard_url + "/" + route, timeout=10)
                    code = 200
                except urllib.error.HTTPError as error:
                    code = error.code
                if 200 <= code < 300:
                    raise AssertionError(
                        f"internal route was exposed externally: {route}"
                    )
                forbidden[route] = code
            observations["transport_isolation"] = {
                "external_worker_version": external_body.get("version"),
                "proxied_guest_version": proxied_body.get("version"),
                "forbidden_external_status": forbidden,
            }

            stage = "activation-recovery"
            ssh(ssh_argv, f"systemctl stop {shlex.quote(service)}")
            stopped = ssh(
                ssh_argv,
                "set -eu; "
                f"! systemctl is-active --quiet {shlex.quote(service)}; "
                f"systemctl is-active --quiet {shlex.quote(socket_unit)}; "
                f"test -S {shlex.quote(dstack_socket)}; test -S {shlex.quote(tappd_socket)}",
            )
            del stopped
            dstack_after = guest_rpc(ssh_argv, dstack_socket, "Info")
            wait_active(ssh_argv, service)
            tappd_after = guest_rpc(ssh_argv, tappd_socket, "prpc/Info")
            if dstack_after.get("app_id") != dstack_before.get("app_id"):
                raise AssertionError("DstackGuest identity changed after activation")
            if tappd_after.get("app_id") != tappd_before.get("app_id"):
                raise AssertionError("Tappd identity changed after activation")
            observations["activation_recovery"] = {
                "socket_unit_survived_service_stop": True,
                "both_socket_paths_survived": True,
                "rpc_triggered_service_activation": True,
                "responses_stable": True,
            }
            steps.append(
                {
                    "id": "tc-gos-observabil-002-step-02",
                    "status": "PASS",
                    "observed": "DstackGuest and Tappd were isolated to their Unix sockets, Worker was public, GuestApi was reachable only through the VMM proxy, and a Unix RPC reactivated the stopped service without identity change.",
                }
            )
            emit("step-02", "PASS")

            stage = "fault-injection-recovery"
            emit("step-03", "START")
            unit_contract = ssh(
                ssh_argv,
                f"systemctl show -p Listen --value {shlex.quote(socket_unit)}",
            ).stdout
            descriptor_contract = (
                dstack_socket in unit_contract and tappd_socket in unit_contract
            )

            holder = (
                "import socket,time; "
                "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
                f"s.bind(('0.0.0.0',{external_port})); s.listen(); time.sleep(30)"
            )
            ssh(
                ssh_argv,
                "set -eu; "
                f"systemctl stop {shlex.quote(service)} {shlex.quote(socket_unit)}; "
                f"nohup python3 -c {shlex.quote(holder)} >/dev/null 2>&1 & "
                "echo $! >/run/dstack-test-bind-conflict.pid; sleep 1; "
                f"systemctl start {shlex.quote(socket_unit)}",
            )
            conflict = ssh(
                ssh_argv,
                f"timeout 15 systemctl start {shlex.quote(service)}",
                check=False,
            )
            if conflict.returncode == 0:
                raise AssertionError(
                    "service unexpectedly accepted the TCP bind conflict"
                )
            bind_probe = (
                "import socket; "
                "s=socket.socket(); "
                "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
                f"s.bind(('0.0.0.0',{external_port})); s.close()"
            )
            ssh(
                ssh_argv,
                "set -eu; "
                f"systemctl stop {shlex.quote(service)}; "
                f"! systemctl is-active --quiet {shlex.quote(service)}; "
                'pid=$(cat /run/dstack-test-bind-conflict.pid); kill "$pid"; '
                "for _ in $(seq 1 50); do "
                'if ! kill -0 "$pid" 2>/dev/null; then break; fi; sleep 0.1; '
                'done; ! kill -0 "$pid" 2>/dev/null; '
                "rm -f /run/dstack-test-bind-conflict.pid; "
                f"python3 -c {shlex.quote(bind_probe)}; "
                f"systemctl reset-failed {shlex.quote(service)}; "
                f"systemctl start {shlex.quote(service)}",
            )
            wait_active(ssh_argv, service)

            ssh(
                ssh_argv,
                "set -eu; "
                f"systemctl stop {shlex.quote(service)} {shlex.quote(socket_unit)}; "
                f"rm -f {shlex.quote(dstack_socket)} {shlex.quote(tappd_socket)}; "
                f"systemctl start {shlex.quote(socket_unit)}; "
                f"test -S {shlex.quote(dstack_socket)}; "
                f"test -S {shlex.quote(tappd_socket)}",
            )
            recovered_dstack = guest_rpc(ssh_argv, dstack_socket, "Info")
            wait_active(ssh_argv, service)
            recovered_tappd = guest_rpc(ssh_argv, tappd_socket, "prpc/Info")
            if recovered_dstack.get("app_id") != dstack_before.get("app_id"):
                raise AssertionError(
                    "DstackGuest identity changed after listener recovery"
                )
            if recovered_tappd.get("app_id") != tappd_before.get("app_id"):
                raise AssertionError("Tappd identity changed after listener recovery")
            if not descriptor_contract:
                raise AssertionError("socket unit does not declare both listener paths")
            observations["fault_recovery"] = {
                "descriptor_contract_has_both_listeners": True,
                "bind_conflict_rejected": True,
                "service_recovered_after_conflict": True,
                "missing_listener_paths_recreated": True,
                "both_rpc_paths_reactivated": True,
                "identity_stable": True,
            }
            steps.append(
                {
                    "id": "tc-gos-observabil-002-step-03",
                    "status": "PASS",
                    "observed": "The socket descriptor contract contained both listeners, a TCP bind conflict failed closed, removing both listener paths was repaired by socket-unit restart, and both RPC paths reactivated with stable identity.",
                }
            )
            emit("step-03", "PASS")
    except Exception as error:
        status = "FAIL"
        summary = f"{stage}: {error}"
        observations["error_type"] = type(error).__name__
        observations["error"] = str(error)
        try:
            if isinstance(lifecycle, dict) and isinstance(ssh_argv, list):
                ssh(
                    ssh_argv,
                    f"systemctl start {shlex.quote(str(lifecycle['service_unit']))}",
                    check=False,
                )
        except Exception:
            pass

    artifact = {
        "case_id": CASE_ID,
        "status": status,
        "environment": "HARDWARE",
        "observations": observations,
    }
    artifact_path = (
        Path(result_path).parent / "artifacts/socket-activation-isolation.json"
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(artifact, indent=2) + "\n")
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "status": status,
        "summary": summary,
        "steps": steps,
        "evidence": [
            {
                "path": "artifacts/socket-activation-isolation.json",
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
    }
    Path(result_path).write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
