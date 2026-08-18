#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify Docker volume persistence, ephemerality, and app isolation."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gos-storage-an-005"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a bounded local command with retained output."""
    return subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False
    )


def ssh(
    ssh_argv: list[str], script: str, timeout: int = 90
) -> subprocess.CompletedProcess[str]:
    """Run a bounded script in a lease-owned guest."""
    return subprocess.run(
        [*ssh_argv, "bash", "-s"],
        input=script,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def query(argv: list[str]) -> dict[str, Any]:
    """Read lease VM state."""
    completed = run(argv, 30)
    if completed.returncode:
        raise AssertionError("failed to query primary lease VM")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise AssertionError("primary lease VM query returned non-object")
    return value


def require_probe(
    completed: subprocess.CompletedProcess[str], phase: str
) -> dict[str, Any]:
    """Require a successful JSON guest probe."""
    if completed.returncode:
        raise AssertionError(f"{phase} failed with exit {completed.returncode}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{phase} returned invalid JSON") from error
    if not isinstance(value, dict):
        raise AssertionError(f"{phase} returned non-object JSON")
    return value


def main() -> int:
    """Run volume persistence and cross-app isolation acceptance."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    values = manifest.get("values", {})
    storage = values.get("storage_lifecycle")
    peer = values.get("volume_isolation_peer")
    status = "PASS"
    summary = "Persistent, ephemeral, and cross-app volume semantics were verified."
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    primary_ssh: list[str] = []
    peer_ssh: list[str] = []
    volume_name = ""
    try:
        capable = (
            isinstance(storage, dict)
            and storage.get("destructive_actions_allowed") is True
            and values.get("destructive_actions_allowed") is True
            and isinstance(values.get("ssh_argv"), list)
            and isinstance(peer, dict)
            and peer.get("destructive_actions_allowed") is True
            and peer.get("app_relation") == "different-compose-and-app-id"
            and isinstance(peer.get("ssh_argv"), list)
        )
        if not capable:
            status = "BLOCKED"
            summary = "fixture lacks lease-owned volume persistence isolation peers"
            observations["missing_capability"] = "volume-persistence-isolation-peer"
        else:
            primary_ssh = [*map(str, values["ssh_argv"])]
            peer_ssh = [*map(str, peer["ssh_argv"])]
            run_hash = hashlib.sha256(
                os.environ["DSTACK_TEST_RUN_ID"].encode()
            ).hexdigest()
            volume_name = f"dstack-test-{run_hash[:20]}"
            primary_marker = hashlib.sha256(
                (run_hash + "-primary").encode()
            ).hexdigest()
            peer_marker = hashlib.sha256((run_hash + "-peer").encode()).hexdigest()
            primary_script = f"""set -eu
volume={volume_name}
marker={primary_marker}
image=
for candidate in $(docker ps --format '{{{{.Image}}}}' | sort -u); do
    if docker run --rm --entrypoint sh "$candidate" -c true >/dev/null 2>&1; then
        image=$candidate
        break
    fi
done
[ -n "$image" ]
docker image inspect "$image" >/dev/null
docker volume rm -f "$volume" >/dev/null 2>&1 || true
docker volume create "$volume" >/dev/null
docker run --rm --entrypoint sh -e MARKER="$marker" -v "$volume:/probe" "$image" -c 'printf %s "$MARKER" > /probe/marker'
readback=$(docker run --rm --entrypoint sh -v "$volume:/probe" "$image" -c 'cat /probe/marker')
[ "$readback" = "$marker" ]
before=$(docker volume ls -q | sort | sha256sum | awk '{{print $1}}')
docker run --rm --entrypoint sh -v /anonymous "$image" -c 'printf transient > /anonymous/marker; test -s /anonymous/marker'
after=$(docker volume ls -q | sort | sha256sum | awk '{{print $1}}')
[ "$before" = "$after" ]
docker run --rm --entrypoint sh --tmpfs /volatile "$image" -c 'printf transient > /volatile/marker; test -s /volatile/marker'
docker run --rm --entrypoint sh --tmpfs /volatile "$image" -c 'test ! -e /volatile/marker'
set +e
docker volume create 'invalid/name' >/tmp/dstack-volume-invalid.out 2>&1
invalid_rc=$?
set -e
[ "$invalid_rc" -ne 0 ]
docker info >/dev/null
jq -cn --arg image_hash "$(printf %s "$image" | sha256sum | awk '{{print $1}}')" --arg volume "$volume" --arg marker_hash "$(printf %s "$marker" | sha256sum | awk '{{print $1}}')" --argjson invalid_rc "$invalid_rc" '{{image_reference_sha256:$image_hash,volume_name:$volume,marker_sha256:$marker_hash,named_volume_recreated:true,anonymous_removed:true,tmpfs_ephemeral:true,invalid_volume_exit_code:$invalid_rc,docker_healthy:true}}'
"""
            primary_before = require_probe(
                ssh(primary_ssh, primary_script, 120), "primary volume lifecycle probe"
            )
            peer_script = f"""set -eu
volume={volume_name}
primary={primary_marker}
peer={peer_marker}
image=
for candidate in $(docker ps --format '{{{{.Image}}}}' | sort -u); do
    if docker run --rm --entrypoint sh "$candidate" -c true >/dev/null 2>&1; then
        image=$candidate
        break
    fi
done
[ -n "$image" ]
docker volume rm -f "$volume" >/dev/null 2>&1 || true
docker volume create "$volume" >/dev/null
if docker run --rm --entrypoint sh -e PRIMARY="$primary" -v "$volume:/probe" "$image" -c 'test -e /probe/marker && test "$(cat /probe/marker)" = "$PRIMARY"'; then exit 42; fi
docker run --rm --entrypoint sh -e PEER="$peer" -v "$volume:/probe" "$image" -c 'printf %s "$PEER" > /probe/marker'
readback=$(docker run --rm --entrypoint sh -v "$volume:/probe" "$image" -c 'cat /probe/marker')
[ "$readback" = "$peer" ]
jq -cn --arg volume "$volume" --arg marker_hash "$(printf %s "$peer" | sha256sum | awk '{{print $1}}')" '{{volume_name:$volume,primary_marker_absent:true,peer_marker_sha256:$marker_hash,app_relation:"different-compose-and-app-id"}}'
"""
            peer_probe = ssh(peer_ssh, peer_script, 120)
            if peer_probe.returncode == 42:
                raise AssertionError(
                    "different-app peer read the primary volume marker"
                )
            peer_result = require_probe(peer_probe, "peer volume isolation probe")
            if run([*map(str, storage["stop_argv"])], 180).returncode:
                raise AssertionError("failed to stop primary lease VM")
            deadline = time.monotonic() + 90
            state = query([*map(str, storage["info_argv"])])
            stopped_statuses = {"stopped", "exited"}
            while (
                state.get("status") not in stopped_statuses
                and time.monotonic() < deadline
            ):
                time.sleep(1)
                state = query([*map(str, storage["info_argv"])])
            if state.get("status") not in stopped_statuses:
                raise AssertionError("primary lease VM did not stop")
            stopped_status = state.get("status")
            if run([*map(str, storage["start_argv"])], 180).returncode:
                raise AssertionError("failed to start primary lease VM")
            deadline = time.monotonic() + 180
            state = query([*map(str, storage["info_argv"])])
            while time.monotonic() < deadline:
                if (
                    state.get("status") == "running"
                    and state.get("boot_progress") == "done"
                    and run([*primary_ssh, "true"], 20).returncode == 0
                ):
                    break
                time.sleep(2)
                state = query([*map(str, storage["info_argv"])])
            else:
                raise AssertionError("restarted primary lease VM did not become ready")
            verify_script = f"""set -eu
volume={volume_name}
marker={primary_marker}
image=
for candidate in $(docker ps --format '{{{{.Image}}}}' | sort -u); do
    if docker run --rm --entrypoint sh "$candidate" -c true >/dev/null 2>&1; then
        image=$candidate
        break
    fi
done
[ -n "$image" ]
readback=$(docker run --rm --entrypoint sh -v "$volume:/probe" "$image" -c 'cat /probe/marker')
[ "$readback" = "$marker" ]
docker volume rm -f "$volume" >/dev/null
docker info >/dev/null
jq -cn '{{marker_persisted_after_vm_restart:true,primary_volume_removed:true,docker_healthy_after_restart:true}}'
"""
            primary_after = require_probe(
                ssh(primary_ssh, verify_script, 120), "post-restart persistence probe"
            )
            peer_cleanup = ssh(
                peer_ssh,
                f"docker volume rm -f {volume_name} >/dev/null\ndocker info >/dev/null\n",
                60,
            )
            if peer_cleanup.returncode:
                raise AssertionError("failed to clean peer volume or recheck Docker")
            observations.update(
                {
                    "primary": primary_before,
                    "peer": peer_result,
                    "restart": primary_after,
                    "stopped_status": stopped_status,
                    "restart_boot_progress": state.get("boot_progress"),
                    "ssh_reconnected": True,
                    "peer_volume_removed": True,
                }
            )
            volume_name = ""
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        status = "FAIL"
        summary = str(error)
        observations["failure"] = summary
    finally:
        if volume_name:
            cleanup = f"docker volume rm -f {volume_name} >/dev/null 2>&1 || true\n"
            if primary_ssh:
                ssh(primary_ssh, cleanup, 30)
            if peer_ssh:
                ssh(peer_ssh, cleanup, 30)
    artifact = {
        "path": "artifacts/volume-persistence-isolation.json",
        "step_id": f"{case_id}-step-01",
        "name": "Volume persistence and isolation",
        "description": "Redacted named, anonymous, tmpfs, restart, peer-isolation, and cleanup observations.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "Lease ownership, Docker health, clean volume baseline, and peer identity relation were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Named, anonymous, and tmpfs lifecycles, VM restart persistence, and same-name peer isolation were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Invalid input rejection, Docker health, marker hashes, and two-guest cleanup were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Only lease-owned VMs and case-scoped Docker volumes are modified; marker values are never retained.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
