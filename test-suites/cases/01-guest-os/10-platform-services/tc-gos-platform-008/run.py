#!/usr/bin/env python3
"""Verify measured normal/privileged Docker policy and cross-CVM isolation."""

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

CASE_ID = "tc-gos-platform-008"


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


def rpc(url: str) -> dict[str, Any]:
    """Call one non-secret Tappd.Info endpoint with bounded startup retries."""
    deadline = time.monotonic() + 45
    last: Exception | None = None
    while time.monotonic() < deadline:
        request = urllib.request.Request(
            url.replace("{method}", "Info"),
            data=b"{}",
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                value = json.load(response)
            if isinstance(value, dict) and value.get("app_id"):
                return value
            raise AssertionError("Tappd.Info response was incomplete")
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            last = error
            time.sleep(1)
    raise AssertionError(f"Tappd.Info did not become ready: {type(last).__name__}")


def identity_hash(value: dict[str, Any]) -> str:
    """Hash public identity fields without retaining their values."""
    selected = {
        name: value.get(name) for name in ("app_id", "instance_id", "device_id")
    }
    return hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()


def target_container(argv: list[str]) -> str:
    """Resolve the unique compose boundary-target container."""
    output = ssh(
        argv,
        "docker ps -aq --filter label=com.docker.compose.service=boundary-target",
    ).stdout.split()
    if len(output) != 1:
        raise AssertionError(f"expected one boundary-target, found {len(output)}")
    return output[0]


def inspect(argv: list[str], container: str) -> dict[str, Any]:
    """Inspect one case-owned container."""
    value = json.loads(ssh(argv, f"docker inspect {shlex.quote(container)}").stdout)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise AssertionError("docker inspect returned an unexpected shape")
    return value[0]


def emit(step: str, state: str) -> None:
    """Emit one live step transition."""
    print(f"STEP {CASE_ID}-{step} {state}", flush=True)


def main() -> int:
    """Run the measured Docker privilege and isolation acceptance matrix."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values", {})
    boundary = values.get("docker_boundary") if isinstance(values, dict) else None
    status = "PASS"
    summary = "Docker daemon and measured container privilege boundary passed"
    observations: dict[str, Any] = {}
    steps: list[dict[str, str]] = []
    stage = "fixture"
    memory_blocked = False
    normal_marker = f"/tmp/dstack-boundary-normal-{manifest.get('lease_id', '')[-10:]}"
    privileged_marker = (
        f"/tmp/dstack-boundary-priv-{manifest.get('lease_id', '')[-10:]}"
    )

    try:
        if not (
            isinstance(boundary, dict)
            and isinstance(boundary.get("normal"), dict)
            and isinstance(boundary.get("privileged"), dict)
        ):
            status = "BLOCKED"
            summary = "missing capability: measured-docker-boundary-pair"
            observations["missing_capability"] = "measured-docker-boundary-pair"
        else:
            normal = boundary["normal"]
            privileged = boundary["privileged"]
            normal_ssh = [str(item) for item in normal["ssh_argv"]]
            privileged_ssh = [str(item) for item in privileged["ssh_argv"]]
            normal_url = str(values["services"]["Tappd"]["url"])
            privileged_url = str(privileged["tappd_url"])

            stage = "baseline"
            emit("step-01", "START")
            if normal.get("compose_sha256") == privileged.get("compose_sha256"):
                raise AssertionError("normal and privileged compose hashes matched")
            normal_identity = rpc(normal_url)
            privileged_identity = rpc(privileged_url)
            normal_identity_hash = identity_hash(normal_identity)
            privileged_identity_hash = identity_hash(privileged_identity)
            if normal_identity_hash == privileged_identity_hash:
                raise AssertionError("normal and privileged app identities matched")
            normal_id = target_container(normal_ssh)
            privileged_id = target_container(privileged_ssh)
            normal_inspect = inspect(normal_ssh, normal_id)
            privileged_inspect = inspect(privileged_ssh, privileged_id)
            observations["baseline"] = {
                "compose_hashes_distinct": True,
                "app_identities_distinct": True,
                "normal_container_present": True,
                "privileged_container_present": True,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": "PASS",
                    "observed": "The fixture exposed one normal and one privileged measured application with distinct compose hashes, app identities, instances, SSH routes, and boundary-target containers.",
                }
            )
            emit("step-01", "PASS")

            stage = "policy-boundary"
            emit("step-02", "START")
            normal_host = normal_inspect.get("HostConfig", {})
            privileged_host = privileged_inspect.get("HostConfig", {})
            normal_mounts = normal_inspect.get("Mounts", [])
            privileged_mounts = privileged_inspect.get("Mounts", [])
            normal_security = [
                str(x).lower() for x in normal_host.get("SecurityOpt") or []
            ]
            normal_cap_drop = [str(x).upper() for x in normal_host.get("CapDrop") or []]
            if normal_host.get("Privileged") is not False:
                raise AssertionError("normal target was privileged")
            if normal_host.get("NetworkMode") != "none" or normal_host.get(
                "PidMode"
            ) not in ("", None):
                raise AssertionError(
                    "normal target gained host network or PID namespace"
                )
            if "ALL" not in normal_cap_drop or not any(
                "no-new-privileges" in x for x in normal_security
            ):
                raise AssertionError(
                    "normal capability/no-new-privileges policy was absent"
                )
            controllers = ssh(
                normal_ssh,
                "cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true",
            ).stdout.split()
            memory_blocked = "memory" not in controllers
            if (
                not memory_blocked
                and int(normal_host.get("Memory") or 0) != 128 * 1024 * 1024
            ):
                raise AssertionError(
                    f"normal memory controller is available but the measured limit "
                    f"was not applied: Memory={normal_host.get('Memory')!r}"
                )
            if int(normal_host.get("PidsLimit") or 0) != 64:
                raise AssertionError("normal PID limit differed from measured compose")
            if normal_mounts:
                raise AssertionError("normal target unexpectedly received mounts")
            if privileged_host.get("Privileged") is not True:
                raise AssertionError(
                    "privileged target did not receive its measured privilege"
                )
            if (
                privileged_host.get("NetworkMode") != "host"
                or privileged_host.get("PidMode") != "host"
            ):
                raise AssertionError(
                    "privileged target lacked measured host namespaces"
                )
            mount_by_dest = {
                str(x.get("Destination")): x
                for x in privileged_mounts
                if isinstance(x, dict)
            }
            root_mount = mount_by_dest.get("/guest-host")
            socket_mount = mount_by_dest.get("/run/dstack.sock")
            if not root_mount or root_mount.get("RW") is not False or not socket_mount:
                raise AssertionError(
                    "privileged guest-root/socket mounts differed from compose"
                )
            ssh(normal_ssh, f"printf normal > {shlex.quote(normal_marker)}")
            ssh(privileged_ssh, f"printf privileged > {shlex.quote(privileged_marker)}")
            ssh(
                normal_ssh,
                f"docker exec {shlex.quote(normal_id)} sh -c 'test ! -e /guest-host && test ! -e /run/dstack.sock'",
            )
            ssh(
                privileged_ssh,
                f"docker exec {shlex.quote(privileged_id)} test -f /guest-host{shlex.quote(privileged_marker)}",
            )
            ssh(privileged_ssh, f"test ! -e {shlex.quote(normal_marker)}")
            ssh(normal_ssh, f"test ! -e {shlex.quote(privileged_marker)}")
            observations["policy"] = {
                "normal_privilege_absent": True,
                "normal_pids_limit_exact": True,
                "normal_memory_limit_exact": not memory_blocked,
                "missing_capability": (
                    "candidate-guest-memory-cgroup" if memory_blocked else None
                ),
                "privileged_declarations_honored": True,
                "privileged_root_is_guest_readonly": True,
                "cross_cvm_markers_isolated": True,
                "physical_host_access_allowed": boundary.get(
                    "physical_host_access_allowed"
                ),
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "BLOCKED" if memory_blocked else "PASS",
                    "observed": (
                        "Docker honored the measured normal restrictions and privileged declarations except that the candidate guest kernel lacks the memory cgroup controller; PIDs, namespaces, capabilities, mounts, sockets, identities, and cross-CVM isolation passed."
                        if memory_blocked
                        else "Docker honored all measured normal restrictions and privileged declarations; the privileged root mount was its own CVM read-only root, while normal and peer CVM state remained isolated."
                    ),
                }
            )
            emit("step-02", "PASS")

            stage = "failure-recovery"
            emit("step-03", "START")
            invalid = ssh(
                normal_ssh, "docker inspect dstack-case-definitely-absent", check=False
            )
            if invalid.returncode == 0:
                raise AssertionError("invalid container lookup succeeded")
            ssh(normal_ssh, f"docker stop -t 10 {shlex.quote(normal_id)}")
            stopped = inspect(normal_ssh, normal_id)
            if stopped.get("State", {}).get("Running") is not False:
                raise AssertionError("normal target did not stop")
            ssh(normal_ssh, f"docker start {shlex.quote(normal_id)}")
            recovered = inspect(normal_ssh, normal_id)
            if recovered.get("State", {}).get("Running") is not True:
                raise AssertionError("normal target did not recover")
            observations["failure_recovery"] = {
                "invalid_lookup_rejected": True,
                "normal_stop_observed": True,
                "normal_start_recovered": True,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "A nonexistent container lookup failed closed; the case-owned normal target stopped, exposed the stopped state, restarted once, and returned to running.",
                }
            )
            emit("step-03", "PASS")

            stage = "final-isolation"
            emit("step-04", "START")
            if identity_hash(rpc(normal_url)) != normal_identity_hash:
                raise AssertionError("normal identity changed")
            if identity_hash(rpc(privileged_url)) != privileged_identity_hash:
                raise AssertionError("privileged identity changed")
            ssh(normal_ssh, "systemctl is-active --quiet docker.service")
            ssh(privileged_ssh, "systemctl is-active --quiet docker.service")
            if target_container(normal_ssh) == target_container(privileged_ssh):
                raise AssertionError(
                    "cross-CVM container identifiers unexpectedly matched"
                )
            observations["final"] = {
                "identities_unchanged": True,
                "docker_services_active": True,
                "container_ids_distinct": True,
            }
            steps.append(
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": "PASS",
                    "observed": "Both measured app identities and Docker services remained stable after recovery, and the two CVMs retained distinct boundary-target container identities.",
                }
            )
            emit("step-04", "PASS")
            if memory_blocked:
                status = "BLOCKED"
                summary = "missing capability: candidate-guest-memory-cgroup"
    except Exception as error:
        status = "FAIL"
        summary = f"{stage}: {type(error).__name__}: {error}"
        observations["failed_stage"] = stage
        observations["error_type"] = type(error).__name__
        observations["error"] = str(error)
    finally:
        if isinstance(boundary, dict):
            for role in ("normal", "privileged"):
                item = boundary.get(role)
                if isinstance(item, dict) and isinstance(item.get("ssh_argv"), list):
                    argv = [str(x) for x in item["ssh_argv"]]
                    ssh(
                        argv,
                        f"rm -f {shlex.quote(normal_marker)} {shlex.quote(privileged_marker)}",
                        check=False,
                    )

    artifact = {
        "case_id": CASE_ID,
        "status": status,
        "environment": "HARDWARE",
        "observations": observations,
    }
    artifact_path = result_dir / "artifacts/docker-boundary.json"
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
                "path": "artifacts/docker-boundary.json",
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
