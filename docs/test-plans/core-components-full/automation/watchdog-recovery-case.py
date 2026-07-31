#!/usr/bin/env python3
"""Verify systemd watchdog replacement and stable guest-agent recovery."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-observabil-005"


def ssh(
    argv: list[str], command: str, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command through the manifest-recorded SSH route."""
    result = subprocess.run(
        [*argv, command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"guest command failed ({result.returncode}): {command!r}; "
            f"stdout={result.stdout[-800:]!r}; stderr={result.stderr[-800:]!r}"
        )
    return result


def unit_state(argv: list[str], unit: str) -> dict[str, str]:
    """Read the bounded watchdog-relevant systemd unit properties."""
    output = ssh(
        argv,
        f"systemctl show {shlex.quote(unit)} "
        "--property=MainPID,WatchdogUSec,ActiveState,SubState,NRestarts --no-pager",
    ).stdout
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def health(argv: list[str], url: str) -> dict[str, Any]:
    """Call the guest-local non-secret Worker.Version endpoint."""
    raw = ssh(
        argv,
        "curl --silent --show-error --fail-with-body --max-time 20 " + shlex.quote(url),
    ).stdout
    value = json.loads(raw)
    if not isinstance(value, dict) or not value.get("version"):
        raise AssertionError("Worker.Version response was incomplete")
    return value


def emit(step: str, state: str) -> None:
    """Emit one live step transition."""
    print(f"STEP {CASE_ID}-{step} {state}", flush=True)


def duration_usec(value: str) -> int:
    """Parse the bounded systemd duration formats used by WatchdogUSec."""
    units = (("min", 60_000_000), ("ms", 1_000), ("us", 1), ("s", 1_000_000))
    for suffix, multiplier in units:
        if value.endswith(suffix):
            return int(float(value[: -len(suffix)]) * multiplier)
    return int(value)


def main() -> int:
    """Run the watchdog failure, recovery, and stability matrix."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values", {})
    lifecycle = values.get("watchdog_lifecycle") if isinstance(values, dict) else None
    ssh_argv = values.get("ssh_argv") if isinstance(values, dict) else None
    status = "PASS"
    summary = "guest-agent watchdog recovery matrix passed"
    steps: list[dict[str, str]] = []
    observations: dict[str, Any] = {}
    stage = "fixture"
    frozen = False
    unit = "dstack-guest-agent.service"

    try:
        if not (
            isinstance(lifecycle, dict)
            and lifecycle.get("destructive_actions_allowed") is True
            and values.get("destructive_actions_allowed") is True
            and isinstance(ssh_argv, list)
            and lifecycle.get("freeze_signal") == "STOP"
        ):
            status = "BLOCKED"
            summary = "missing capability: guest-agent-watchdog-lifecycle"
            observations["missing_capability"] = "guest-agent-watchdog-lifecycle"
        else:
            unit = str(lifecycle["service_unit"])
            url = str(lifecycle["health_url"])
            start = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

            stage = "baseline"
            emit("step-01", "START")
            before = unit_state(ssh_argv, unit)
            before_health = health(ssh_argv, url)
            pid_before = int(before.get("MainPID", "0"))
            watchdog_usec = duration_usec(before.get("WatchdogUSec", "0"))
            if (
                pid_before <= 1
                or watchdog_usec <= 0
                or before.get("ActiveState") != "active"
            ):
                raise AssertionError(f"invalid watchdog baseline: {before}")
            observations["baseline"] = {
                "active": True,
                "main_pid_positive": True,
                "watchdog_usec": watchdog_usec,
                "version": before_health["version"],
                "restart_count": int(before.get("NRestarts", "0")),
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": "PASS",
                    "observed": "The case-owned guest-agent was active with a positive MainPID, a nonzero systemd watchdog interval, and a healthy guest-local Worker.Version endpoint.",
                }
            )
            emit("step-01", "PASS")

            stage = "watchdog-replacement"
            emit("step-02", "START")
            ssh(
                ssh_argv,
                f"systemctl kill --kill-who=main --signal=STOP {shlex.quote(unit)}",
            )
            frozen = True
            timeout = max(90.0, watchdog_usec / 1_000_000 * 3)
            deadline = time.monotonic() + timeout
            after: dict[str, str] = {}
            while time.monotonic() < deadline:
                after = unit_state(ssh_argv, unit)
                current_pid = int(after.get("MainPID", "0"))
                if (
                    current_pid > 1
                    and current_pid != pid_before
                    and after.get("ActiveState") == "active"
                ):
                    frozen = False
                    break
                time.sleep(1)
            else:
                raise AssertionError(f"watchdog did not replace frozen PID: {after}")
            recovered_health = health(ssh_argv, url)
            pid_recovered = int(after["MainPID"])
            observations["recovery"] = {
                "pid_replaced": True,
                "active": True,
                "version_stable": recovered_health.get("version")
                == before_health.get("version"),
                "restart_count": int(after.get("NRestarts", "0")),
            }
            if not observations["recovery"]["version_stable"]:
                raise AssertionError("Worker.Version changed after watchdog recovery")
            steps.append(
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "Freezing the service main process suppressed sd_notify heartbeats; systemd replaced it with a different active MainPID and Worker.Version recovered unchanged.",
                }
            )
            emit("step-02", "PASS")

            stage = "recovery-stability"
            emit("step-03", "START")
            time.sleep(watchdog_usec / 1_000_000 + 5)
            stable = unit_state(ssh_argv, unit)
            if (
                stable.get("ActiveState") != "active"
                or int(stable.get("MainPID", "0")) != pid_recovered
            ):
                raise AssertionError("watchdog continued replacing the healthy service")
            health(ssh_argv, url)
            invalid = ssh(
                ssh_argv,
                "curl --silent --output /dev/null --write-out %{http_code} "
                "--max-time 20 http://127.0.0.1:8090/prpc/DstackGuest.Info",
                check=False,
            )
            try:
                invalid_code = int(invalid.stdout.strip())
            except ValueError as error:
                raise AssertionError(
                    "invalid-route probe returned no HTTP status"
                ) from error
            if 200 <= invalid_code < 300:
                raise AssertionError(
                    "internal DstackGuest method was exposed externally"
                )
            journal = ssh(
                ssh_argv,
                f"journalctl -u {shlex.quote(unit)} --since {shlex.quote(start)} --no-pager",
            ).stdout.lower()
            observations["stability"] = {
                "main_pid_stable_for_additional_interval": True,
                "active": True,
                "invalid_route_status": invalid_code,
                "journal_mentions_watchdog": "watchdog" in journal,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "The recovered MainPID remained stable for another watchdog interval, health remained available, and the external listener rejected an internal DstackGuest route.",
                }
            )
            emit("step-03", "PASS")
    except Exception as error:
        status = "FAIL"
        summary = f"{stage}: {error}"
        observations["error_type"] = type(error).__name__
        observations["error"] = str(error)
    finally:
        if isinstance(ssh_argv, list) and isinstance(lifecycle, dict):
            if frozen:
                ssh(
                    ssh_argv,
                    f"systemctl kill --kill-who=main --signal=CONT {shlex.quote(unit)}",
                    check=False,
                )
            ssh(ssh_argv, f"systemctl start {shlex.quote(unit)}", check=False)

    artifact = {
        "case_id": CASE_ID,
        "status": status,
        "environment": "HARDWARE",
        "observations": observations,
    }
    artifact_path = result_dir / "artifacts/watchdog-recovery.json"
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
                "path": "artifacts/watchdog-recovery.json",
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
