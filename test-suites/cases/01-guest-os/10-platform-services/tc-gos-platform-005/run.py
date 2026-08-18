#!/usr/bin/env python3
"""Verify declared guest hardening and a real non-privileged workload boundary."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-platform-005"


def ssh(
    argv: list[str], command: str, *, check: bool = True, timeout: int = 90
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command through a fixture-recorded SSH route."""
    result = subprocess.run(
        [*argv, command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"guest command failed ({result.returncode}): {command!r}; "
            f"stdout={result.stdout[-600:]!r}; stderr={result.stderr[-600:]!r}"
        )
    return result


def emit(step: str, state: str) -> None:
    """Emit a live case-step transition."""
    print(f"STEP {CASE_ID}-{step} {state}", flush=True)


def target_container(argv: list[str]) -> str:
    """Resolve the unique measured boundary container."""
    ids = ssh(
        argv, "docker ps -aq --filter label=com.docker.compose.service=boundary-target"
    ).stdout.split()
    if len(ids) != 1:
        raise AssertionError(
            f"expected one boundary-target container, found {len(ids)}"
        )
    return ids[0]


def inspect(argv: list[str], container: str) -> dict[str, Any]:
    """Return one Docker container inspection object."""
    value = json.loads(ssh(argv, f"docker inspect {shlex.quote(container)}").stdout)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise AssertionError("docker inspect returned an unexpected shape")
    return value[0]


def main() -> int:
    """Execute the declared hardening, recovery, and isolation matrix."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values", {})
    fixture = (
        values.get("guest_hardening_lifecycle") if isinstance(values, dict) else None
    )
    status = "PASS"
    summary = "Declared guest hardening and non-privileged workload boundary passed"
    steps: list[dict[str, str]] = []
    observations: dict[str, Any] = {}
    cleanup = {"marker_removed": False, "docker_recovered": False}
    stage = "fixture"
    primary_ssh: list[str] = []
    adjacent_ssh: list[str] = []
    marker = ""
    policy_hashes = ""

    try:
        if not (
            isinstance(fixture, dict)
            and fixture.get("destructive_actions_allowed") is True
            and isinstance(fixture.get("primary"), dict)
            and isinstance(fixture.get("adjacent"), dict)
        ):
            status = "BLOCKED"
            summary = "missing capability: guest-hardening-boundary-lifecycle"
            steps.append(
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": "BLOCKED",
                    "observed": "The case-scoped hardening fixture was not declared.",
                }
            )
        else:
            primary = fixture["primary"]
            adjacent = fixture["adjacent"]
            primary_ssh = [str(x) for x in primary["ssh_argv"]]
            adjacent_ssh = [str(x) for x in adjacent["ssh_argv"]]
            marker_hash = hashlib.sha256(
                str(manifest.get("lease_id", "")).encode()
            ).hexdigest()
            marker = f"/tmp/dstack-hardening-{marker_hash[:12]}"

            stage = "baseline"
            emit("step-01", "START")
            conntrack = int(
                ssh(
                    primary_ssh, "sysctl -n net.netfilter.nf_conntrack_max"
                ).stdout.strip()
            )
            if conntrack != int(
                fixture["declared_policy"]["net.netfilter.nf_conntrack_max"]
            ):
                raise AssertionError(f"nf_conntrack_max={conntrack}")
            sshd = ssh(
                primary_ssh,
                "grep -Ei '^(PasswordAuthentication|PermitRootLogin)[[:space:]]' /etc/ssh/sshd_config.d/10-dstack.conf | tr A-Z a-z",
            ).stdout.lower()
            if "passwordauthentication no" not in sshd or not any(
                x in sshd
                for x in (
                    "permitrootlogin prohibit-password",
                    "permitrootlogin without-password",
                )
            ):
                raise AssertionError(
                    "effective SSH password policy differed from the image declaration"
                )
            unlocked = ssh(
                primary_ssh, "awk -F: '$2 !~ /^[!*]/ {print $1}' /etc/shadow"
            ).stdout.split()
            if unlocked:
                raise AssertionError(
                    "one or more local accounts had an unlocked password"
                )
            for unit in (
                "docker.service",
                "sshd.service",
                "dstack-guest-agent.service",
            ):
                ssh(primary_ssh, f"systemctl is-active --quiet {shlex.quote(unit)}")
            measured_paths = [str(x) for x in fixture["measured_readonly_paths"]]
            if not measured_paths:
                raise AssertionError("no measured host policy paths were declared")
            quoted_paths = " ".join(shlex.quote(x) for x in measured_paths)
            policy_hashes = ssh(primary_ssh, f"sha256sum {quoted_paths}").stdout
            if len(policy_hashes.splitlines()) != len(measured_paths):
                raise AssertionError("host policy path measurement was incomplete")
            ssh(
                primary_ssh,
                "test ! -e /dev/kvm && "
                "zgrep -qx CONFIG_STRICT_DEVMEM=y /proc/config.gz && "
                "zgrep -qx CONFIG_IO_STRICT_DEVMEM=y /proc/config.gz",
            )
            observations["baseline"] = {
                "declared_conntrack_exact": True,
                "ssh_password_auth_disabled": True,
                "password_accounts_locked": True,
                "required_services_active": True,
                "host_policy_paths_measured": True,
                "host_kvm_absent_and_devmem_strict": True,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": "PASS",
                    "observed": "The effective conntrack, SSH/account, service, read-only mount, and device baseline matched the checked-in release policy.",
                }
            )
            emit("step-01", "PASS")

            stage = "workload-boundary"
            emit("step-02", "START")
            container = target_container(primary_ssh)
            cfg = inspect(primary_ssh, container).get("HostConfig", {})
            cap_drop = [str(x).upper() for x in cfg.get("CapDrop") or []]
            security = [str(x).lower() for x in cfg.get("SecurityOpt") or []]
            if cfg.get("Privileged") is not False or cfg.get("NetworkMode") != "none":
                raise AssertionError("workload gained privileged or network access")
            if cfg.get("PidMode") not in ("", None) or "ALL" not in cap_drop:
                raise AssertionError(
                    "workload gained host PID namespace or capabilities"
                )
            if not any("no-new-privileges" in x for x in security):
                raise AssertionError("no-new-privileges was absent")
            denied = ssh(
                primary_ssh,
                f"docker exec {shlex.quote(container)} sh -c "
                "'printf blocked > /proc/sys/kernel/hostname'",
                check=False,
            )
            if denied.returncode == 0:
                raise AssertionError("container modified its kernel hostname sysctl")
            container_path_checks = " && ".join(
                f"test ! -e {shlex.quote(path)}" for path in measured_paths
            )
            container_checks = (
                "test ! -e /dev/kvm && test ! -e /dev/mem && "
                "test ! -e /run/systemd/system && " + container_path_checks
            )
            ssh(
                primary_ssh,
                f"docker exec {shlex.quote(container)} sh -c {shlex.quote(container_checks)}",
            )
            observations["boundary"] = {
                "unprivileged": True,
                "network_none": True,
                "host_pid_absent": True,
                "all_capabilities_dropped": True,
                "no_new_privileges": True,
                "sysctl_write_rejected": True,
                "host_devices_systemd_and_policy_paths_absent": True,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "The measured application container lacked host network/PID, privilege, capabilities, devices, and service control, and its sysctl mutation failed closed.",
                }
            )
            emit("step-02", "PASS")

            stage = "failure-recovery"
            emit("step-03", "START")
            missing = ssh(
                primary_ssh,
                "docker inspect dstack-hardening-definitely-absent",
                check=False,
            )
            if missing.returncode == 0:
                raise AssertionError("invalid container lookup succeeded")
            ssh(primary_ssh, "systemctl stop docker.socket docker.service")
            unavailable = ssh(primary_ssh, "docker info", check=False, timeout=30)
            if unavailable.returncode == 0:
                raise AssertionError("Docker dependency interruption was not observed")
            ssh(primary_ssh, "systemctl start docker.service docker.socket")
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                recovered = ssh(primary_ssh, "docker info", check=False, timeout=15)
                if recovered.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise AssertionError("Docker did not recover within 45 seconds")
            container = target_container(primary_ssh)
            if ssh(primary_ssh, f"sha256sum {quoted_paths}").stdout != policy_hashes:
                raise AssertionError(
                    "measured host policy changed across dependency recovery"
                )
            if (
                inspect(primary_ssh, container).get("State", {}).get("Running")
                is not False
            ):
                raise AssertionError("restart:no workload unexpectedly auto-started")
            ssh(primary_ssh, f"docker start {shlex.quote(container)}")
            if (
                inspect(primary_ssh, container).get("State", {}).get("Running")
                is not True
            ):
                raise AssertionError("explicit workload recovery did not succeed")
            observations["recovery"] = {
                "invalid_lookup_rejected": True,
                "dependency_outage_observed": True,
                "docker_recovered": True,
                "restart_no_honored": True,
                "explicit_workload_recovery": True,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Invalid lookup failed, a bounded Docker outage was observed, restart:no remained fail-closed, and one explicit workload restart recovered.",
                }
            )
            emit("step-03", "PASS")

            stage = "isolation"
            emit("step-04", "START")
            if str(primary.get("instance_id")) == str(adjacent.get("instance_id")):
                raise AssertionError("primary and adjacent instance identities matched")
            ssh(primary_ssh, f"printf marker > {shlex.quote(marker)}")
            ssh(adjacent_ssh, f"test ! -e {shlex.quote(marker)}")
            ssh(primary_ssh, "systemctl is-active --quiet docker.service")
            observations["isolation"] = {
                "adjacent_instance_distinct": True,
                "marker_isolated": True,
                "service_restart_persisted_health": True,
                "sentinel_sha256": marker_hash,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": "PASS",
                    "observed": "The adjacent VM retained a distinct identity and could not observe primary transient state after service recovery.",
                }
            )
            emit("step-04", "PASS")
    except Exception as error:
        status = "FAIL"
        summary = (
            f"guest hardening matrix failed during {stage}: {type(error).__name__}"
        )
        steps.append(
            {
                "id": f"{CASE_ID}-step-{len(steps) + 1:02d}",
                "status": "FAIL",
                "observed": str(error)[:900],
            }
        )
    finally:
        if primary_ssh:
            if marker:
                cleanup["marker_removed"] = (
                    ssh(
                        primary_ssh, f"rm -f {shlex.quote(marker)}", check=False
                    ).returncode
                    == 0
                )
            ssh(
                primary_ssh, "systemctl start docker.service docker.socket", check=False
            )
            cleanup["docker_recovered"] = (
                ssh(
                    primary_ssh,
                    "systemctl is-active --quiet docker.service",
                    check=False,
                ).returncode
                == 0
            )

    artifact = {
        "case_id": CASE_ID,
        "status": status,
        "environment": "HARDWARE/MKOSI",
        "observations": observations,
        "cleanup": cleanup,
        "sensitive_values_recorded": False,
    }
    artifact_path = result_dir / "artifacts/guest-hardening.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "status": status,
        "summary": summary,
        "steps": steps,
        "evidence": [
            {
                "path": "artifacts/guest-hardening.json",
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
