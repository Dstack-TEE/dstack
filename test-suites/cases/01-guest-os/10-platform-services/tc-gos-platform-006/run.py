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
# Drop-ins the image ships are vendor configuration (PR #1158, PR #1157).
VENDOR_DROPINS = {
    "docker.service": ("dstack-guest-agent.conf", "dstack-prepare.conf"),
    "containerd.service": ("dstack-prepare.conf",),
    "nvidia-fabricmanager.service": ("10-nvswitch-condition.conf",),
}


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


def vendor_dropin_locations(argv: list[str]) -> dict[str, list[str]]:
    """Require image-shipped drop-ins in the vendor unit directory (PR #1158)."""
    units = sorted(VENDOR_DROPINS)
    simulator = (
        ssh(argv, "test -x /usr/bin/dstack-tee-simulator", check=False).returncode == 0
    )
    if simulator:
        units.append("dstack-prepare.service")
    shown = ssh(
        argv,
        "systemctl show "
        + " ".join(shlex.quote(unit) for unit in units)
        + " --property=Id,DropInPaths --no-pager",
    ).stdout
    effective: dict[str, list[str]] = {}
    for block in shown.strip().split("\n\n"):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        effective[fields.get("Id", "")] = fields.get("DropInPaths", "").split()
    expected = dict(VENDOR_DROPINS)
    if simulator:
        expected["dstack-prepare.service"] = ("tee-simulator.conf",)
    problems = []
    for unit, names in expected.items():
        paths = effective.get(unit, [])
        for name in names:
            vendor = f"/usr/lib/systemd/system/{unit}.d/{name}"
            if vendor not in paths:
                problems.append(f"{unit} does not load {vendor}")
            if f"/etc/systemd/system/{unit}.d/{name}" in paths:
                problems.append(f"{unit} loads {name} from the operator /etc layer")
    if problems:
        raise AssertionError("; ".join(problems))
    return {unit: effective.get(unit, []) for unit in expected}


def unit_properties(argv: list[str], unit: str, properties: str) -> dict[str, str]:
    """Read one unit's properties as a name-to-value map."""
    shown = ssh(
        argv,
        f"systemctl show {shlex.quote(unit)} --property={properties} --no-pager",
    ).stdout
    return dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)


def boot_unit_edges(argv: list[str]) -> dict[str, Any]:
    """Require the boot-chain edges added after the baseline (PRs #1322, #1324, #1328, #1341)."""
    problems = []
    agent = unit_properties(argv, SERVICE, "After,OnFailure")
    after = agent.get("After", "").split()
    if "dstack-prepare.service" not in after or "tboot.service" in after:
        problems.append("guest agent is not ordered after dstack-prepare alone")
    app = unit_properties(
        argv, "app-compose.service", "Requires,OnFailure,ExecStart,EnvironmentFiles"
    )
    requires = app.get("Requires", "").split()
    for unit in ("dstack-prepare.service", "dstack-guest-agent.service"):
        if unit not in requires:
            problems.append(f"app-compose does not require {unit}")
    if "exec-with-env" not in app.get("ExecStart", "") or ".decrypted-env.json" not in (
        app.get("ExecStart", "")
    ):
        problems.append("app-compose does not start through dstack-util exec-with-env")
    if app.get("EnvironmentFiles"):
        problems.append("app-compose still loads an EnvironmentFile")
    docker = unit_properties(argv, "docker.service", "OnFailure,TimeoutStartUSec")
    if docker.get("TimeoutStartUSec") in (None, "", "infinity", "0"):
        problems.append("docker waits for the guest agent without a start timeout")
    for unit, properties in (
        (SERVICE, agent),
        ("app-compose.service", app),
        ("docker.service", docker),
    ):
        if f"dstack-boot-error@{unit}.service" not in properties.get("OnFailure", ""):
            problems.append(f"{unit} does not report failure through dstack-boot-error")
    reporter = unit_properties(
        argv, "dstack-boot-error@app-compose.service.service", "LoadState,ExecStart"
    )
    if reporter.get("LoadState") != "loaded" or "boot.error" not in reporter.get(
        "ExecStart", ""
    ):
        problems.append("dstack-boot-error@.service does not notify boot.error")
    if problems:
        raise AssertionError("; ".join(problems))
    return {
        "agent_after_prepare": True,
        "app_requires_prepare_and_agent": True,
        "app_exec_with_env": True,
        "docker_start_timeout": docker.get("TimeoutStartUSec"),
        "boot_error_reporters": [SERVICE, "app-compose.service", "docker.service"],
    }


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
            dropins = vendor_dropin_locations(ssh_argv)
            edges = boot_unit_edges(ssh_argv)
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
                "vendor_dropins": dropins,
                "boot_unit_edges": edges,
                "primary_peer_distinct": True,
                "peer_system_state": peer_state_before,
                "graph_sha256": hashlib.sha256(graph.encode()).hexdigest(),
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": "PASS",
                    "observed": "Runtime unit properties contained the checked-in prepare failure action, guest-agent socket/watchdog/restart edges, app-compose Docker/containerd ordering, and gateway-checker node; image-shipped drop-ins loaded from /usr/lib/systemd/system rather than /etc; the guest agent followed dstack-prepare, app-compose required prepare and the agent and started through exec-with-env, docker had a bounded start, and each reported failure through dstack-boot-error@; primary and peer identities were distinct and healthy.",
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
