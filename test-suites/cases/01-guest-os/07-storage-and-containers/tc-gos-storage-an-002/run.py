#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify isolated ephemeral Docker success and failure cleanup."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-storage-an-002"
GUEST_PROBE = r"""
set -eu
phase=baseline
on_error() {
    rc=$?
    jq -cn --arg phase "$phase" --argjson rc "$rc" '{probe_error_phase:$phase,probe_exit_code:$rc}'
    exit 0
}
trap on_error ERR
system_pid=$(pidof dockerd | awk '{print $1}')
system_socket=$(stat -Lc '%d:%i' /var/run/docker.sock)
containers_before=$(docker ps -aq | sort | sha256sum | awk '{print $1}')
images_before=$(docker images -q | sort -u | sha256sum | awk '{print $1}')

phase=active_start
/usr/bin/ephemeral-docker.sh events --until 5s >/dev/null 2>&1 &
helper_pid=$!
tmpdir=
for _ in $(seq 1 100); do
    line=$(ps -eo args | grep -E '(^|/)dockerd .*--data-root /tmp/tmp\.' | head -n 1 || true)
    tmpdir=$(printf %s "$line" | sed -n 's#.*--data-root \([^ ]*\)/docker-data.*#\1#p')
    [ -n "$tmpdir" ] && break
    kill -0 "$helper_pid" 2>/dev/null || break
    sleep 0.1
done
phase=active_tmpdir
[ -n "$tmpdir" ]
phase=active_containerd_socket
[ -S "$tmpdir/containerd.sock" ]
phase=active_docker_socket
for _ in $(seq 1 100); do
    [ -S "$tmpdir/docker.sock" ] && break
    kill -0 "$helper_pid" 2>/dev/null || break
    sleep 0.1
done
[ -S "$tmpdir/docker.sock" ]
phase=active_roots
[ -d "$tmpdir/docker-data" ]
[ -d "$tmpdir/docker-exec" ]
phase=active_processes
active_processes=$(ps -eo args | grep -F "$tmpdir" | grep -E '(^|/)(dockerd|containerd) ' | wc -l)
[ "$active_processes" -ge 2 ]
phase=valid_cleanup
wait "$helper_pid"
valid_rc=$?
[ ! -e "$tmpdir" ]
if ps -eo args | grep -F "$tmpdir" | grep -E '^(dockerd|containerd) ' >/dev/null; then
    exit 41
fi

phase=invalid_cleanup
trace=$(mktemp)
set +e
trap - ERR
bash -x /usr/bin/ephemeral-docker.sh dstack-test-invalid-subcommand > /dev/null 2>"$trace"
invalid_rc=$?
trap on_error ERR
set -e
invalid_tmpdir=$(sed -n 's/^+ TMPDIR=//p' "$trace" | head -n 1)
rm -f "$trace"
phase=invalid_status
[ "$invalid_rc" -ne 0 ]
phase=invalid_tmpdir
[ -n "$invalid_tmpdir" ]
phase=invalid_path_cleanup
[ ! -e "$invalid_tmpdir" ]
phase=invalid_process_cleanup
if ps -eo args | grep -F "$invalid_tmpdir" | grep -E '(^|/)(dockerd|containerd) ' >/dev/null; then
    exit 42
fi

phase=system_stability
[ "$(pidof dockerd | awk '{print $1}')" = "$system_pid" ]
[ "$(stat -Lc '%d:%i' /var/run/docker.sock)" = "$system_socket" ]
containers_after=$(docker ps -aq | sort | sha256sum | awk '{print $1}')
images_after=$(docker images -q | sort -u | sha256sum | awk '{print $1}')
[ "$containers_before" = "$containers_after" ]
[ "$images_before" = "$images_after" ]

jq -cn --argjson active "$active_processes" --argjson valid_rc "$valid_rc"     --argjson invalid_rc "$invalid_rc" --arg containers "$containers_after"     --arg images "$images_after"     '{active_ephemeral_processes:$active,valid_exit_code:$valid_rc,invalid_exit_code:$invalid_rc,valid_cleanup:true,invalid_cleanup:true,system_daemon_stable:true,system_socket_stable:true,container_inventory_sha256:$containers,image_inventory_sha256:$images}'
"""


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


def main() -> int:
    """Run the ephemeral Docker lifecycle acceptance check."""
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
    ssh_argv = values.get("ssh_argv")
    status = "PASS"
    summary = "Ephemeral Docker isolated and cleaned success and failure runtimes."
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    try:
        if not isinstance(ssh_argv, list):
            status = "BLOCKED"
            summary = "fixture lacks a lease-owned guest SSH capability"
            observations["missing_capability"] = "ephemeral-docker-guest"
        else:
            completed = subprocess.run(
                [*map(str, ssh_argv), "bash", "-s"],
                input=GUEST_PROBE,
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )
            if completed.returncode:
                raise AssertionError(
                    f"ephemeral Docker guest probe failed with exit {completed.returncode}"
                )
            probe = json.loads(completed.stdout)
            if "probe_error_phase" in probe:
                raise AssertionError(
                    f"ephemeral Docker probe failed in safe phase "
                    f"{probe['probe_error_phase']} with exit {probe['probe_exit_code']}"
                )
            if probe["valid_exit_code"] != 0:
                raise AssertionError("valid ephemeral Docker command failed")
            if probe["invalid_exit_code"] == 0:
                raise AssertionError("invalid ephemeral Docker command was accepted")
            if probe["active_ephemeral_processes"] < 2:
                raise AssertionError("ephemeral daemon isolation was not observed")
            repository = pathlib.Path(runtime["repository"])
            source = (repository / "os/common/rootfs/ephemeral-docker.sh").read_text()
            guards = [
                "TMPDIR=$(mktemp -d)",
                '--data-root "$TMPDIR/docker-data"',
                '--exec-root "$TMPDIR/docker-exec"',
                'rm -rf "$TMPDIR"',
                "exit ${EXIT_CODE:-$exit_code}",
            ]
            if any(guard not in source for guard in guards):
                raise AssertionError("candidate helper lacks required isolation guards")
            observations.update(probe)
            observations["source_guards"] = len(guards)
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

    artifact = {
        "path": "artifacts/ephemeral-docker-lifecycle.json",
        "step_id": f"{case_id}-step-01",
        "name": "Ephemeral Docker lifecycle",
        "description": "Daemon counts, exit codes, cleanup booleans, and redacted inventory hashes.",
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
                    "observed": "System daemon and redacted inventory baselines were captured.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Isolated temporary daemons and valid/invalid command status forwarding were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Temporary resources disappeared and the system daemon and inventories remained stable.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "The helper runs only inside the lease guest and does not reboot any VM or host.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
