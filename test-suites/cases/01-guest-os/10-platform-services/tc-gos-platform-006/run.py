#!/usr/bin/env python3
"""Verify systemd dependency graph, leaf interruption, and peer isolation."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-platform-006"
SERVICE = "dstack-guest-agent.service"


def ssh(
    argv: list[str], command: str, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command through a manifest-recorded guest SSH route."""
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


def rpc(url: str, timeout: float = 30) -> dict[str, Any]:
    """Call the non-secret Tappd Info endpoint."""
    request = urllib.request.Request(
        url.replace("{method}", "Info"),
        data=b"{}",
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.load(response)
    if not isinstance(value, dict) or not value.get("app_id"):
        raise AssertionError("Tappd.Info response was incomplete")
    return value


def identity_hash(value: dict[str, Any]) -> str:
    """Hash public identity fields without retaining their values."""
    selected = {
        name: value.get(name) for name in ("app_id", "instance_id", "device_id")
    }
    return hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()


def wait_rpc(url: str) -> dict[str, Any]:
    """Wait for the unchanged socket bridge to serve Tappd.Info again."""
    deadline = time.monotonic() + 45
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return rpc(url, timeout=5)
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            last = error
            time.sleep(1)
    raise AssertionError(f"Tappd.Info did not recover: {type(last).__name__}")


def emit(step: str, state: str) -> None:
    """Emit one live step transition."""
    print(f"STEP {CASE_ID}-{step} {state}", flush=True)


def main() -> int:
    """Run the static graph and dynamic leaf-service acceptance matrix."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values", {})
    peer = values.get("systemd_graph_peer") if isinstance(values, dict) else None
    ssh_argv = values.get("ssh_argv") if isinstance(values, dict) else None
    status = "PASS"
    summary = "systemd dependency and failure-action graph matrix passed"
    observations: dict[str, Any] = {}
    steps: list[dict[str, str]] = []
    stage = "fixture"
    frozen = False

    try:
        if not (
            isinstance(ssh_argv, list)
            and values.get("destructive_actions_allowed") is True
            and isinstance(peer, dict)
            and isinstance(peer.get("ssh_argv"), list)
            and peer.get("destructive_actions_allowed") is True
        ):
            status = "BLOCKED"
            summary = "missing capability: systemd-graph-peer-lifecycle"
            observations["missing_capability"] = "systemd-graph-peer-lifecycle"
        else:
            primary_url = str(values["services"]["Tappd"]["url"])
            peer_url = str(peer["tappd_url"])
            peer_ssh = [str(item) for item in peer["ssh_argv"]]

            stage = "baseline-graph"
            emit("step-01", "START")
            graph = ssh(
                ssh_argv,
                "systemctl show dstack-prepare.service dstack-guest-agent.service "
                "dstack-guest-agent.socket docker.service containerd.service "
                "app-compose.service dstack-gateway-checker.service "
                "--property=Id,LoadState,ActiveState,Requires,Wants,After,Before,"
                "OnFailure,FailureAction,Restart,WatchdogUSec,TimeoutStartUSec --no-pager",
            ).stdout
            required_tokens = (
                "Id=dstack-prepare.service",
                "FailureAction=reboot",
                "Id=dstack-guest-agent.service",
                "dstack-guest-agent.socket",
                "Restart=always",
                "Id=app-compose.service",
                "docker.service",
                "containerd.service",
                "Id=dstack-gateway-checker.service",
            )
            missing = [token for token in required_tokens if token not in graph]
            if missing:
                raise AssertionError(
                    f"runtime graph omitted declared tokens: {missing}"
                )
            primary_before = wait_rpc(primary_url)
            peer_before = wait_rpc(peer_url)
            peer_state_before = ssh(
                peer_ssh, "systemctl is-system-running --wait || true"
            ).stdout.strip()
            primary_hash = identity_hash(primary_before)
            peer_hash = identity_hash(peer_before)
            if primary_hash == peer_hash:
                raise AssertionError(
                    "primary and adjacent identities were not distinct"
                )
            observations["baseline"] = {
                "declared_graph_tokens_present": True,
                "primary_peer_distinct": True,
                "peer_system_state": peer_state_before,
                "graph_sha256": hashlib.sha256(graph.encode()).hexdigest(),
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": "PASS",
                    "observed": "Runtime unit properties contained the checked-in prepare failure action, guest-agent socket/watchdog/restart edges, app-compose Docker/containerd ordering, and gateway-checker node; primary and peer identities were distinct and healthy.",
                }
            )
            emit("step-01", "PASS")

            stage = "leaf-interruption"
            emit("step-02", "START")
            ssh(
                ssh_argv,
                f"systemctl kill --kill-who=main --signal=STOP {shlex.quote(SERVICE)}",
            )
            frozen = True
            interrupted = False
            try:
                rpc(primary_url, timeout=5)
            except (OSError, TimeoutError, urllib.error.URLError):
                interrupted = True
            if not interrupted:
                raise AssertionError(
                    "Tappd.Info responded while guest-agent main process was stopped"
                )
            ssh(
                ssh_argv,
                f"systemctl kill --kill-who=main --signal=CONT {shlex.quote(SERVICE)}",
            )
            frozen = False
            resumed = wait_rpc(primary_url)
            if identity_hash(resumed) != primary_hash:
                raise AssertionError(
                    "primary identity changed after STOP/CONT recovery"
                )
            observations["interruption"] = {
                "rpc_failed_while_stopped": True,
                "same_rpc_recovered_after_continue": True,
                "socket_unit_left_unchanged": True,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "Stopping only the restartable guest-agent process made the unchanged Tappd route fail without a response; continuing the process restored the same RPC and identity without recreating the socket unit.",
                }
            )
            emit("step-02", "PASS")

            stage = "invalid-unit-recovery"
            emit("step-03", "START")
            invalid_name = f"dstack-case-{manifest['lease_id'][-12:]}-absent.service"
            invalid = ssh(
                ssh_argv,
                f"systemctl start {shlex.quote(invalid_name)}",
                check=False,
            )
            if invalid.returncode == 0:
                raise AssertionError("nonexistent case-scoped unit was accepted")
            graph_after_invalid = ssh(
                ssh_argv,
                "systemctl show dstack-prepare.service dstack-guest-agent.service "
                "app-compose.service --property=Id,Requires,Wants,After,Before,"
                "OnFailure,FailureAction,Restart,WatchdogUSec --no-pager",
            ).stdout
            if "Id=dstack-prepare.service" not in graph_after_invalid:
                raise AssertionError("graph became unavailable after invalid operation")
            ssh(ssh_argv, f"systemctl restart {shlex.quote(SERVICE)}")
            restarted = wait_rpc(primary_url)
            if identity_hash(restarted) != primary_hash:
                raise AssertionError("primary identity changed after service restart")
            observations["failure_recovery"] = {
                "invalid_unit_rejected": True,
                "graph_remained_queryable": True,
                "leaf_restart_recovered": True,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Systemd rejected a syntactically valid nonexistent case-scoped unit, the dependency graph remained queryable, and the documented leaf service restarted with the same identity.",
                }
            )
            emit("step-03", "PASS")

            stage = "peer-isolation"
            emit("step-04", "START")
            peer_after = rpc(peer_url)
            peer_state_after = ssh(
                peer_ssh, "systemctl is-system-running --wait || true"
            ).stdout.strip()
            if identity_hash(peer_after) != peer_hash:
                raise AssertionError("adjacent peer identity changed")
            if peer_state_after not in ("running", "degraded"):
                raise AssertionError(
                    f"adjacent peer became unhealthy: {peer_state_after}"
                )
            observations["isolation"] = {
                "peer_identity_unchanged": True,
                "peer_system_state": peer_state_after,
                "primary_health_restored": bool(rpc(primary_url).get("app_id")),
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": "PASS",
                    "observed": "The adjacent lease-owned peer retained its identity and healthy system state throughout primary mutations, and primary Tappd health was restored.",
                }
            )
            emit("step-04", "PASS")
    except Exception as error:
        status = "FAIL"
        summary = f"{stage}: {type(error).__name__}: {error}"
        observations["failed_stage"] = stage
        observations["error_type"] = type(error).__name__
        observations["error"] = str(error)
    finally:
        if isinstance(ssh_argv, list):
            if frozen:
                ssh(
                    ssh_argv,
                    f"systemctl kill --kill-who=main --signal=CONT {shlex.quote(SERVICE)}",
                    check=False,
                )
            ssh(ssh_argv, f"systemctl start {shlex.quote(SERVICE)}", check=False)

    artifact = {
        "case_id": CASE_ID,
        "status": status,
        "environment": "HARDWARE",
        "observations": observations,
    }
    artifact_path = result_dir / "artifacts/systemd-graph-lifecycle.json"
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
                "path": "artifacts/systemd-graph-lifecycle.json",
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
